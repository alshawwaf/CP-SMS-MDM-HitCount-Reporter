#!/usr/bin/env python3
"""Offline test suite for python/hitcount.py: mocked 2-domain MDS from
tests/stubs/fixtures.json plus unit checks. Requirements: python3 only."""
import contextlib
import datetime
import importlib.util
import io
import json
import os
import ssl
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

SPEC = importlib.util.spec_from_file_location(
    "hc", os.path.join(REPO, "python", "hitcount.py"))
hc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hc)

with open(os.path.join(HERE, "stubs", "fixtures.json")) as f:
    FIX = json.load(f)

PASS = FAIL = 0
CAPTURED = []


def check(desc, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("PASS  %s" % desc)
    else:
        FAIL += 1
        print("FAIL  %s %s" % (desc, extra))


def slice_page(objs, off, size, key="objects"):
    sl = objs[off:off + size]
    return {key: sl, "from": off + 1 if sl else off,
            "to": off + len(sl), "total": len(objs)}


def fake_web_api(server, port, command, payload, sid, ctx, timeout=120):
    if command == "login":
        return {"sid": "sid:%s" % (payload.get("domain") or "MDS")}
    if command == "logout":
        return {}
    off = payload.get("offset", 0)
    domain = sid.split(":", 1)[1]
    if domain == "MDS":   # domain-less login = standalone/SMS context
        domain = ""
    if command == "show-domains":
        if sid != "sid:MDS":
            raise hc.ApiError("not in MDS context")
        return slice_page([{"name": d} for d in FIX["domains"]], off, 1)
    if command == "show-access-layers":
        # real API quirk: container key is "access-layers", not "objects"
        names = FIX["layers"].get(domain, [])
        return slice_page([{"name": n} for n in names], off, 1,
                          key="access-layers")
    if command == "show-access-rulebase":
        name = payload.get("name")
        if name not in FIX["rulebase"]:
            raise hc.ApiError("Requested object not found")
        if payload.get("show-hits") is not True:
            raise hc.ApiError("show-hits missing")
        hs = payload.get("hits-settings") or {}
        CAPTURED.append({"layer": name, "domain": domain,
                         "from": hs.get("from-date"), "to": hs.get("to-date"),
                         "target": hs.get("target", "")})
        return slice_page(FIX["rulebase"][name], off, 2, key="rulebase")
    raise hc.ApiError("unexpected command %s" % command)


hc.web_api = fake_web_api


def run(argv):
    CAPTURED.clear()
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = hc.main(argv + ["--api-key", "FAKE"])
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


def runj(argv):
    code, out, _ = run(argv + ["--json"])
    return code, json.loads(out)


# --- end-to-end scenarios ----------------------------------------------------
c, recs = runj([])
check("default run: 7 rules, exit 0", c == 0 and len(recs) == 7,
      str([r["name"] for r in recs]))
check("hits values parsed", any(r["hits"] == 12345 for r in recs))
check("section attributed to rule inside it",
      any(r["name"] == "Allow-Mgmt-SSH" and r["section"] == "Management"
          for r in recs))
check("disabled rule flagged",
      any(r["name"] == "Block-SMTP" and r["enabled"] is False for r in recs))

today = datetime.date.today()
expect_from = today - datetime.timedelta(days=hc.WINDOW_DAYS)
expect_to_api = today + datetime.timedelta(days=1)   # to-date is exclusive of its day
check("default window sent to API (from = today-182d, to = today+1d inclusive)",
      all(x["from"] == expect_from.isoformat()
          and x["to"] == expect_to_api.isoformat()
          for x in CAPTURED), str(CAPTURED[:1]))
_, out_default, _ = run([])
check("display shows the user's end date (today), not the +1 API value",
      today.isoformat() in out_default
      and expect_to_api.isoformat() not in out_default)

c, recs = runj(["--zero-only"])
check("--zero-only: exactly the 2 unused rules", c == 0 and len(recs) == 2
      and {r["name"] for r in recs} == {"Block-Telnet", "Block-SMTP"})

c, recs = runj(["--min-hits", "500"])
check("--min-hits 500 keeps 3 rules", c == 0 and len(recs) == 3
      and all(r["hits"] >= 500 for r in recs))

c, recs = runj(["--top", "1"])
check("--top 1 = the most-hit rule", c == 0 and len(recs) == 1
      and recs[0]["hits"] == 12345)

c, recs = runj(["--domain", "CMA-UK"])
check("--domain CMA-UK only", c == 0 and len(recs) == 2
      and all(r["domain"] == "CMA-UK" for r in recs))

c, recs = runj(["--layer", "France"])
check("--layer substring filter", c == 0 and len(recs) == 5)

c, recs = runj(["--from", "2026-01-01", "--to", "2026-03-31"])
check("explicit window forwarded (to-date + 1 day, inclusive of Mar 31)",
      CAPTURED and CAPTURED[0]["from"] == "2026-01-01"
      and CAPTURED[0]["to"] == "2026-04-01")

c, recs = runj(["--target", "fw-paris"])
check("--target forwarded to hits-settings",
      CAPTURED and all(x["target"] == "fw-paris" for x in CAPTURED))

c, recs = runj(["--min-hits", "999999"])
check("no rules over threshold: exit 2", c == 2 and recs == [])

c, out, _ = run([])
check("table footer summarizes", "7 rules shown (2 zero-hit) across 2 domain(s)"
      in out)
check("table marks disabled rule", "(disabled)" in out)
check("last-hit trimmed to date", "2026-07-21" in out)

c, out, err = run(["--from", "bad-date"])
check("invalid --from rejected (exit 2 from argparse)", c == 2)

c, out, err = run(["--zero-only", "--min-hits", "5"])
check("--zero-only + --min-hits rejected", c == 2)

c, out, err = run(["--domain", "CMA-NOPE"])
check("unknown --domain: exit 1", c == 1)

# --- unit probes ---------------------------------------------------------------
flat = list(hc.flatten_rules(FIX["rulebase"]["Standard_France Network"]))
check("flatten: 5 rules out of section+rules", len(flat) == 5)
check("flatten: section name attached", flat[0][1] == "Management")
check("obj_name: inline object", hc.obj_name({"name": "Accept"}) == "Accept")
check("obj_name: uid string passthrough", hc.obj_name("abc-uid") == "abc-uid")
f, t = hc.default_window(datetime.date(2026, 7, 22))
check("default_window math", f == datetime.date(2026, 1, 21)
      and t == datetime.date(2026, 7, 22))
check("api_to_date adds one day", hc.api_to_date(datetime.date(2026, 7, 22))
      == "2026-07-23")
ctx = hc.make_ssl_context("10.0.0.1", False, False)
check("remote TLS verification enforced by default",
      ctx.verify_mode == ssl.CERT_REQUIRED)

# --- standalone SMS mode (show-domains returns nothing) ------------------------
with open(os.path.join(HERE, "stubs", "fixtures-sms.json")) as f:
    SMS = json.load(f)
FIX.clear()
FIX.update(SMS)
c, recs = runj([])
check("SMS mode: all rules reported, labeled (local)",
      c == 0 and len(recs) == 4
      and all(r["domain"] == "(local)" for r in recs),
      str(recs))
c, recs = runj(["--zero-only"])
check("SMS mode: --zero-only finds the unused rule", c == 0
      and [r["name"] for r in recs] == ["Block-Telnet"])
c, out, _ = run([])
check("SMS mode: footer counts one (local) domain",
      "4 rules shown (1 zero-hit) across 1 domain(s)" in out, out)

print()
print("RESULT: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
