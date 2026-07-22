#!/usr/bin/env python3
"""
hitcount_sdk.py - Report per-rule Access Policy HIT COUNTS across all Domains
(CMAs) of a Multi-Domain Management server - or of a standalone Security
Management Server (no domains -> the one local database, labeled "(local)") -
using the official Check Point Management API Python SDK (cpapi).

The remote-friendly variant: run it from your laptop/jump host. It shares its
flattening, filtering and rendering logic with ../python/hitcount.py; only the
transport differs.

Sessions & rate limiting
------------------------
Same design as the FW-Locator SDK version: read-only sessions are opened once
per domain, their ids cached in ~/.hitcount_sdk_sessions.json (mode 600) and
reused across runs with ZERO logins until the server expires them (~10 min
idle). --logout ends them and clears the cache; --fresh forces new logins.
Login bursts that still trip the server's rate limiter (err_too_many_requests)
are retried with backoff automatically.

Prerequisites: pip install cp-mgmt-api-sdk ; API access allowed from your
machine (SmartConsole -> Manage & Settings -> Blades -> Management API), and
the server certificate fingerprint approved on first connect
(--unsafe-auto-accept for trust-on-first-use).

Examples:
  ./hitcount_sdk.py -m 203.0.113.99 --api-key "$MDM_KEY" --zero-only
  ./hitcount_sdk.py -m 203.0.113.99 --api-key "$MDM_KEY" --from 2026-01-01 --top 10
  ./hitcount_sdk.py -m 203.0.113.99 --user admin --domain CMA-EMEA --json

Exit codes: 0 = rules reported, 2 = nothing matched the filters, 1 = error.
"""

import argparse
import getpass
import json
import os
import sys
import time

# reuse the flatten / record / filter / render logic of the stdlib version
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                os.pardir, "python"))
import hitcount as core  # noqa: E402

try:
    from cpapi import APIClient, APIClientArgs
except ImportError:
    print("ERROR: the Check Point SDK is not installed. Run: "
          "pip install cp-mgmt-api-sdk", file=sys.stderr)
    sys.exit(1)

CACHE_FILE = os.path.expanduser("~/.hitcount_sdk_sessions.json")
MDS_KEY = "(mds)"


class SdkError(Exception):
    pass


def parse_args(argv):
    p = argparse.ArgumentParser(
        description="Per-rule hit counts across MDS domains "
                    "(official cpapi SDK transport).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)

    win = p.add_argument_group("time window")
    win.add_argument("--from", dest="from_date", type=core.valid_date,
                     metavar="YYYY-MM-DD",
                     help="start of the window (default: %d days ago)"
                          % core.WINDOW_DAYS)
    win.add_argument("--to", dest="to_date", type=core.valid_date,
                     metavar="YYYY-MM-DD",
                     help="end of the window (default: today)")
    win.add_argument("--target", help="count only hits recorded by this "
                                      "enforcing firewall/cluster")

    scope = p.add_argument_group("filters")
    scope.add_argument("--domain", help="only this domain/CMA (default: all)")
    scope.add_argument("--layer", help="only access layers containing this text")
    scope.add_argument("--zero-only", action="store_true",
                       help="only rules with 0 hits (cleanup candidates)")
    scope.add_argument("--min-hits", type=int, metavar="N",
                       help="only rules with at least N hits")
    scope.add_argument("--top", type=int, metavar="N",
                       help="show the N most-hit rules")

    auth = p.add_argument_group("authentication")
    auth.add_argument("--api-key", help="Login with an API key")
    auth.add_argument("--user", help="Login with this username")
    auth.add_argument("--password",
                      help="Password for --user (prompts or reads "
                           "MGMT_CLI_PASSWORD if omitted)")

    conn = p.add_argument_group("connection")
    conn.add_argument("-m", "--management", default="127.0.0.1",
                      help="Management server address (default: 127.0.0.1)")
    conn.add_argument("--port", type=int, default=443,
                      help="Web API port (default: 443)")
    conn.add_argument("--unsafe-auto-accept", action="store_true",
                      help="Auto-accept the server certificate fingerprint on "
                           "first connect (trust-on-first-use)")

    sess = p.add_argument_group("session cache")
    sess.add_argument("--fresh", action="store_true",
                      help="Ignore cached sessions and log in from scratch")
    sess.add_argument("--logout", action="store_true",
                      help="Log out of every session at the end and clear the "
                           "cache (use on your last run)")

    p.add_argument("--json", action="store_true", help="Emit JSON instead of a table")
    args = p.parse_args(argv)
    if not args.api_key and not args.user:
        p.error("choose an auth mode: --api-key KEY or --user U")
    if args.user and not args.password:
        args.password = os.environ.get("MGMT_CLI_PASSWORD") or getpass.getpass(
            "Password for %s: " % args.user)
    if args.zero_only and args.min_hits is not None:
        p.error("--zero-only and --min-hits are mutually exclusive")
    dfrom, dto = core.default_window()
    args.from_date = args.from_date or dfrom
    args.to_date = args.to_date or dto
    if args.from_date > args.to_date:
        p.error("--from (%s) is after --to (%s)" % (args.from_date, args.to_date))
    return args


# --------------------------------------------------------------------------- #
# Session cache (login once per domain, reuse until the server expires it)
# --------------------------------------------------------------------------- #
def host_key(args):
    return "%s:%d" % (args.management, args.port)


def load_cache():
    try:
        with open(CACHE_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_cache(cache):
    fd = os.open(CACHE_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cache, f)


def make_client(args, sid=None):
    client = APIClient(APIClientArgs(server=args.management, port=args.port,
                                     unsafe_auto_accept=args.unsafe_auto_accept,
                                     sid=sid))
    if client.check_fingerprint() is False:
        raise SdkError("server fingerprint was not accepted "
                       "(rerun with --unsafe-auto-accept or approve it)")
    return client


def do_login(client, args, domain=None):
    last = "login failed"
    for delay in (0, 10, 20, 30):
        if delay:
            print("! rate-limited by the server, retrying in %ds..." % delay,
                  file=sys.stderr)
            time.sleep(delay)
        if args.api_key:
            res = client.login_with_api_key(args.api_key, domain=domain,
                                            read_only=True)
        else:
            res = client.login(args.user, args.password, domain=domain,
                               read_only=True)
        if res.success:
            return
        last = res.error_message or "login failed"
        if "too many requests" not in str(last).lower() \
                and "too_many_requests" not in str(last).lower():
            break
    raise SdkError(last)


def connect(args, cache, domain=None):
    key = domain or MDS_KEY
    sid = None if args.fresh else cache.get(host_key(args), {}).get(key)
    if sid:
        client = make_client(args, sid=sid)
        if client.api_call("show-session").success:
            return client
        client.close_connection()
    client = make_client(args)
    do_login(client, args, domain)
    cache.setdefault(host_key(args), {})[key] = client.sid
    save_cache(cache)
    return client


def release(client, args, cache, domain=None):
    if args.logout:
        try:
            client.api_call("logout")
        except Exception:
            pass
        cache.get(host_key(args), {}).pop(domain or MDS_KEY, None)
        save_cache(cache)
        client.sid = None
    client.close_connection()


# --------------------------------------------------------------------------- #
# Queries
# --------------------------------------------------------------------------- #
def query_list(client, command, payload=None, container_key="objects"):
    res = client.api_query(command, details_level="standard",
                           container_key=container_key, payload=payload)
    if not res.success:
        raise SdkError("%s failed: %s" % (command, res.error_message))
    return res.data or []


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    hits_from = args.from_date.isoformat()
    hits_to = args.to_date.isoformat()
    cache = load_cache()

    client = connect(args, cache)
    try:
        try:
            domains = [o["name"] for o in query_list(client, "show-domains")]
        except SdkError:
            domains = []
    finally:
        release(client, args, cache)

    targets = domains if domains else [None]
    if args.domain:
        wanted = args.domain.lower()
        targets = [d for d in targets if d and d.lower() == wanted]
        if not targets:
            print("Error: domain '%s' not found." % args.domain, file=sys.stderr)
            return 1

    # to-date is exclusive of its own day in the API - send the next day so
    # the window includes the user's end date (see core.api_to_date)
    hits_settings = {"from-date": hits_from, "to-date": core.api_to_date(args.to_date)}
    if args.target:
        hits_settings["target"] = args.target

    records = []
    for domain in targets:
        label = domain or "(local)"
        try:
            client = connect(args, cache, domain)
        except SdkError as exc:
            print("! login failed for domain %s: %s" % (label, exc),
                  file=sys.stderr)
            continue
        try:
            layers = [o["name"] for o in
                      query_list(client, "show-access-layers",
                                 container_key="access-layers")]
            if args.layer:
                layers = [l for l in layers if args.layer.lower() in l.lower()]
            for layer in layers:
                try:
                    items = query_list(client, "show-access-rulebase",
                                       payload={"name": layer,
                                                "show-hits": True,
                                                "hits-settings": hits_settings,
                                                "use-object-dictionary": False},
                                       container_key="rulebase")
                except SdkError as exc:
                    print("! %s / %s: %s" % (label, layer, exc), file=sys.stderr)
                    continue
                for rule, section in core.flatten_rules(items):
                    records.append(core.build_rule_record(label, layer, rule,
                                                          section))
        except SdkError as exc:
            print("! query failed in domain %s: %s" % (label, exc),
                  file=sys.stderr)
        finally:
            release(client, args, cache, domain)

    records = core.apply_filters(records, args)
    core.output(records, args, (hits_from, hits_to))
    return 0 if records else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except SdkError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        sys.exit(1)
