#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hitcount.py - Report per-rule Access Policy HIT COUNTS across all Domains
(CMAs) of a Check Point Multi-Domain Management (MDM/MDS) server, or of a
standalone Security Management Server (no domains found -> the one local
database is swept and results are labeled "(local)").

For every domain it discovers the access layers, pulls the rulebase with hit
counters (show-access-rulebase + show-hits), and prints one line per rule:
domain, layer, rule number/name, action, hits, level and last-hit date.
The classic use case is unused-rule cleanup: --zero-only lists every rule
that took no hits in the time window.

Time window: the last 6 months (182 days) up to today by default. Override
with --from / --to (YYYY-MM-DD). --target narrows the counters to hits
recorded by one specific enforcing firewall.

Auth modes (pick one; default is --local):
  --local              Login-as-root on the MDS (default). Runs 'mgmt_cli login -r true'.
  --api-key KEY        Login with an API key.
  --user U [--password P]
                       Username/password. Prompts (or reads MGMT_CLI_PASSWORD).

TLS: certificates are verified by default; verification is skipped
automatically only for loopback targets. Remote self-signed: --ca-file <pem>
(preferred) or --insecure (last resort). --verify forces verification.

Filters:
  --domain NAME        Only this domain/CMA (default: all)
  --layer SUBSTR       Only access layers whose name contains SUBSTR
  --zero-only          Only rules with 0 hits in the window (cleanup candidates)
  --min-hits N         Only rules with at least N hits
  --top N              The N most-hit rules overall (sorted by hits, descending)

Examples:
  ./hitcount.py                                   # all domains, last 6 months
  ./hitcount.py --zero-only                       # unused rules everywhere
  ./hitcount.py --from 2026-01-01 --to 2026-06-30 --domain CMA-EMEA
  ./hitcount.py --target fw-paris --top 10 --json

Exit codes: 0 = rules reported, 2 = nothing matched the filters, 1 = error.
"""

import argparse
import datetime
import getpass
import ipaddress
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

DEFAULT_MGMT = "127.0.0.1"
DEFAULT_PORT = 443
PAGE = 100
WINDOW_DAYS = 182  # ~6 months
SEP = "─" * 66


class ApiError(Exception):
    def __init__(self, message, details=None):
        super().__init__(message)
        self.details = details or {}


# --------------------------------------------------------------------------- #
# Web API transport (same policy as the FW-Locator project)
# --------------------------------------------------------------------------- #
def is_loopback(server):
    if server == "localhost":
        return True
    try:
        return ipaddress.ip_address(server).is_loopback
    except ValueError:
        return False


def make_ssl_context(server, verify, insecure, ca_file=None):
    if ca_file:
        return ssl.create_default_context(cafile=ca_file)
    ctx = ssl.create_default_context()
    if insecure or (is_loopback(server) and not verify):
        if not is_loopback(server):
            print("! WARNING: TLS certificate verification disabled (--insecure); "
                  "credentials sent to %s can be intercepted. Prefer --ca-file."
                  % server, file=sys.stderr)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def web_api(server, port, command, payload, sid, ctx, timeout=120):
    url = "https://%s:%d/web_api/%s" % (server, port, command)
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if sid:
        headers["X-chkp-sid"] = sid
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            err = json.loads(body)
        except ValueError:
            err = {"message": body or ("HTTP %s" % exc.code)}
        raise ApiError(err.get("message", "HTTP %s" % exc.code), err)
    except urllib.error.URLError as exc:
        hint = ""
        if "CERTIFICATE_VERIFY_FAILED" in str(exc.reason):
            hint = (" - the server certificate is not trusted; pass --ca-file "
                    "(or --insecure to skip verification)")
        raise ApiError("Cannot reach %s:%d (%s)%s" % (server, port, exc.reason, hint))


class Session:
    def __init__(self, args):
        self.server = args.management
        self.port = args.port
        self.ctx = make_ssl_context(args.management, args.verify, args.insecure,
                                    args.ca_file)
        if args.api_key:
            self.mode = "apikey"
        elif args.user:
            self.mode = "user"
        else:
            self.mode = "local"
        self.api_key = args.api_key
        self.user = args.user
        self.password = args.password
        if self.mode == "user" and not self.password:
            self.password = os.environ.get("MGMT_CLI_PASSWORD") or getpass.getpass(
                "Password for %s: " % self.user)

    def login(self, domain=None):
        if self.mode == "local":
            return self._login_root(domain)
        payload = {}
        if self.mode == "apikey":
            payload["api-key"] = self.api_key
        else:
            payload["user"] = self.user
            payload["password"] = self.password
        if domain:
            payload["domain"] = domain
        resp = web_api(self.server, self.port, "login", payload, None, self.ctx)
        return resp["sid"]

    def _login_root(self, domain):
        cmd = ["mgmt_cli", "login", "-r", "true", "--format", "json"]
        if domain:
            cmd += ["domain", domain]
        if self.server not in (DEFAULT_MGMT, "localhost"):
            cmd += ["-m", self.server]
        if self.port != DEFAULT_PORT:
            cmd += ["--port", str(self.port)]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except FileNotFoundError:
            raise ApiError("mgmt_cli not found. --local only works on the "
                           "management server; use --api-key or --user remotely.")
        except subprocess.CalledProcessError as exc:
            raise ApiError("mgmt_cli login -r true failed: %s"
                           % exc.output.decode("utf-8", "replace").strip())
        return json.loads(out.decode("utf-8"))["sid"]

    def logout(self, sid):
        try:
            web_api(self.server, self.port, "logout", {}, sid, self.ctx)
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Queries
# --------------------------------------------------------------------------- #
def _paged(sess, sid, command, extra, container="objects", details="standard"):
    items, offset = [], 0
    while True:
        payload = {"limit": PAGE, "offset": offset, "details-level": details}
        payload.update(extra)
        resp = web_api(sess.server, sess.port, command, payload, sid, sess.ctx)
        page = resp.get(container, [])
        items += page
        to = resp.get("to", 0)
        total = resp.get("total", 0)
        if not page or to >= total:
            break
        offset = to
    return items


def list_domains(sess, sid):
    return [o["name"] for o in _paged(sess, sid, "show-domains", {})]


def list_access_layers(sess, sid):
    # NB: this command's container key is "access-layers", not "objects"
    return [o["name"] for o in _paged(sess, sid, "show-access-layers", {},
                                      container="access-layers")]


def fetch_rulebase(sess, sid, layer, hits_from, hits_to, target):
    hits_settings = {"from-date": hits_from, "to-date": hits_to}
    if target:
        hits_settings["target"] = target
    extra = {
        "name": layer,
        "show-hits": True,
        "hits-settings": hits_settings,
        "use-object-dictionary": False,
    }
    return _paged(sess, sid, "show-access-rulebase", extra, container="rulebase")


def flatten_rules(items):
    """Yield (rule, section-name) for every access-rule, expanding sections."""
    for it in items or []:
        if it.get("type") == "access-section":
            for child in it.get("rulebase") or []:
                if child.get("type") == "access-rule":
                    yield child, it.get("name") or ""
        elif it.get("type") == "access-rule":
            yield it, ""


def obj_name(value):
    """Action/track may be an inline object, a plain string or absent."""
    if isinstance(value, dict):
        return value.get("name") or "-"
    return str(value) if value else "-"


def build_rule_record(domain, layer, rule, section):
    hits = rule.get("hits") or {}

    def iso(key):
        d = hits.get(key) or {}
        return d.get("iso-8601") or ""

    return {
        "domain": domain,
        "layer": layer,
        "section": section,
        "rule-number": rule.get("rule-number"),
        "uid": rule.get("uid"),
        "name": rule.get("name") or "(unnamed)",
        "action": obj_name(rule.get("action")),
        "enabled": bool(rule.get("enabled", True)),
        "hits": int(hits.get("value") or 0),
        "level": hits.get("level") or "zero",
        "percentage": hits.get("percentage") or "",
        "first-hit": iso("first-date"),
        "last-hit": iso("last-date"),
    }


# --------------------------------------------------------------------------- #
# Filters + output
# --------------------------------------------------------------------------- #
def apply_filters(records, args):
    out = records
    if args.zero_only:
        out = [r for r in out if r["hits"] == 0]
    if args.min_hits is not None:
        out = [r for r in out if r["hits"] >= args.min_hits]
    if args.top is not None:
        out = sorted(out, key=lambda r: r["hits"], reverse=True)[:args.top]
    return out


def _print_table(headers, rows):
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    print("  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)))


def output(records, args, window):
    if args.json:
        print(json.dumps(records, indent=2))
        return
    if not records:
        print("No rules matched the filters (window %s .. %s)." % window)
        return
    headers = ["DOMAIN(CMA)", "LAYER", "NO", "RULE", "ACTION", "HITS", "LEVEL",
               "LAST HIT"]
    rows = []
    for r in records:
        name = r["name"] + ("" if r["enabled"] else "  (disabled)")
        rows.append([r["domain"], r["layer"], r["rule-number"] if r["rule-number"]
                     is not None else "-", name, r["action"], r["hits"],
                     r["level"], (r["last-hit"] or "-")[:10]])
    _print_table(headers, rows)
    zero = sum(1 for r in records if r["hits"] == 0)
    domains = len({r["domain"] for r in records})
    print()
    print("%d rules shown (%d zero-hit) across %d domain(s) | window: %s .. %s"
          % (len(records), zero, domains, window[0], window[1]))


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def valid_date(text):
    try:
        return datetime.datetime.strptime(text, "%Y-%m-%d").date()
    except ValueError:
        raise argparse.ArgumentTypeError(
            "invalid date %r (expected YYYY-MM-DD)" % text)


def default_window(today=None):
    to_d = today or datetime.date.today()
    from_d = to_d - datetime.timedelta(days=WINDOW_DAYS)
    return from_d, to_d


def api_to_date(to_date):
    """The management API treats a hits-settings to-date as the START of that
    day, so a plain end date excludes that day's own hits (e.g. a default
    window ending 'today' would hide everything that happened today). Send the
    following day to the API so the window is inclusive of the user's end date.
    The user-facing output still shows the original end date."""
    return (to_date + datetime.timedelta(days=1)).isoformat()


def parse_args(argv):
    p = argparse.ArgumentParser(
        description="Report per-rule Access Policy hit counts across all "
                    "MDS domains (CMAs).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)

    win = p.add_argument_group("time window")
    win.add_argument("--from", dest="from_date", type=valid_date, metavar="YYYY-MM-DD",
                     help="start of the hit-count window (default: %d days ago)"
                          % WINDOW_DAYS)
    win.add_argument("--to", dest="to_date", type=valid_date, metavar="YYYY-MM-DD",
                     help="end of the hit-count window (default: today)")
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
                       help="show the N most-hit rules (sorted by hits)")

    auth = p.add_argument_group("authentication")
    auth.add_argument("--local", dest="mode_local", action="store_true",
                      help="Login-as-root on the MDS (default)")
    auth.add_argument("--api-key", help="Login with an API key")
    auth.add_argument("--user", help="Login with this username")
    auth.add_argument("--password",
                      help="Password for --user (avoid on shared systems - "
                           "visible in the process list; prompts or reads "
                           "MGMT_CLI_PASSWORD if omitted)")

    conn = p.add_argument_group("connection")
    conn.add_argument("-m", "--management", default=DEFAULT_MGMT,
                      help="Management server address (default: 127.0.0.1)")
    conn.add_argument("--port", type=int, default=DEFAULT_PORT,
                      help="Web API port (default: 443)")
    conn.add_argument("--ca-file", metavar="PEM",
                      help="CA / certificate bundle to verify the server against")
    conn.add_argument("--verify", action="store_true",
                      help="Force TLS verification even for localhost")
    conn.add_argument("--insecure", action="store_true",
                      help="Skip TLS verification (last resort; prefer --ca-file)")

    p.add_argument("--json", action="store_true", help="Emit JSON instead of a table")
    args = p.parse_args(argv)
    if args.insecure and (args.verify or args.ca_file):
        p.error("--insecure cannot be combined with --verify/--ca-file")
    if args.zero_only and args.min_hits is not None:
        p.error("--zero-only and --min-hits are mutually exclusive")

    dfrom, dto = default_window()
    args.from_date = args.from_date or dfrom
    args.to_date = args.to_date or dto
    if args.from_date > args.to_date:
        p.error("--from (%s) is after --to (%s)" % (args.from_date, args.to_date))
    return args


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    hits_from = args.from_date.isoformat()
    hits_to = args.to_date.isoformat()          # for display
    hits_to_api = api_to_date(args.to_date)     # inclusive of the end day

    sess = Session(args)
    sid0 = sess.login()
    try:
        try:
            domains = list_domains(sess, sid0)
        except ApiError:
            domains = []
    finally:
        sess.logout(sid0)

    targets = domains if domains else [None]
    if args.domain:
        wanted = args.domain.lower()
        targets = [d for d in targets if d and d.lower() == wanted]
        if not targets:
            print("Error: domain '%s' not found." % args.domain, file=sys.stderr)
            return 1

    records = []
    for domain in targets:
        label = domain or "(local)"
        try:
            sid = sess.login(domain)
        except ApiError as exc:
            print("! login failed for domain %s: %s" % (label, exc), file=sys.stderr)
            continue
        try:
            layers = list_access_layers(sess, sid)
            if args.layer:
                layers = [l for l in layers if args.layer.lower() in l.lower()]
            for layer in layers:
                try:
                    items = fetch_rulebase(sess, sid, layer, hits_from,
                                           hits_to_api, args.target)
                except ApiError as exc:
                    print("! %s / %s: %s" % (label, layer, exc), file=sys.stderr)
                    continue
                for rule, section in flatten_rules(items):
                    records.append(build_rule_record(label, layer, rule, section))
        except ApiError as exc:
            print("! query failed in domain %s: %s" % (label, exc), file=sys.stderr)
        finally:
            sess.logout(sid)

    records = apply_filters(records, args)
    output(records, args, (hits_from, hits_to))
    return 0 if records else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except ApiError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        sys.exit(1)
