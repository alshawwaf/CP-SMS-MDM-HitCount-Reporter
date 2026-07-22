#!/bin/bash
# End-to-end tests for the mgmt_cli and clish implementations, run against
# stub mgmt_cli / clish executables (tests/stubs/) that emulate the
# Management API - including hit-count semantics (show-hits, hits-settings
# date validation, capture of the settings the scripts actually send) and
# R82.10 clish quirks. Requirements: bash, python3, jq.
set -u
TESTDIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$TESTDIR")"
export PATH="$TESTDIR/stubs/bin:$PATH"
export HITS_FIXTURES="$TESTDIR/stubs/fixtures.json"
export STUB_CAPTURE="$TESTDIR/.capture.jsonl"
chmod +x "$TESTDIR/stubs/bin/mgmt_cli" "$TESTDIR/stubs/bin/clish"

M="$REPO/mgmt_cli/hitcount.sh"
C="$REPO/clish/hitcount_clish.sh"
PASS=0; FAIL=0; LAST_OUT=""

t() {  # t <expected_exit> <desc> -- cmd args...
    local exp="$1" desc="$2"; shift 3
    local rc
    LAST_OUT="$("$@" 2>&1)"; rc=$?
    if [ "$rc" -eq "$exp" ]; then
        PASS=$((PASS+1)); printf 'PASS exit=%d  %s\n' "$rc" "$desc"
    else
        FAIL=$((FAIL+1)); printf 'FAIL exit=%d (want %d)  %s\n----\n%s\n----\n' "$rc" "$exp" "$desc" "$LAST_OUT"
    fi
}
has() {
    if printf '%s' "$LAST_OUT" | grep -qF -- "$2"; then
        PASS=$((PASS+1)); printf 'PASS output   %s\n' "$1"
    else
        FAIL=$((FAIL+1)); printf 'FAIL output   %s\n  wanted: %s\n----\n%s\n----\n' "$1" "$2" "$LAST_OUT"
    fi
}
hasnt() {
    if printf '%s' "$LAST_OUT" | grep -qF -- "$2"; then
        FAIL=$((FAIL+1)); printf 'FAIL output   %s\n  must NOT contain: %s\n----\n%s\n----\n' "$1" "$2" "$LAST_OUT"
    else
        PASS=$((PASS+1)); printf 'PASS output   %s\n' "$1"
    fi
}
check_capture_window() {  # asserts every captured hits-settings uses the default window
    python3 - "$STUB_CAPTURE" <<'PYEOF'
import datetime, json, sys
lines = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
today = datetime.date.today()
exp_from = today - datetime.timedelta(days=182)
exp_to = today + datetime.timedelta(days=1)   # to-date is exclusive of its day
ok = bool(lines) and all(
    x["to"] == exp_to.isoformat() and x["from"] == exp_from.isoformat()
    for x in lines)
sys.exit(0 if ok else 1)
PYEOF
}

echo "=================== mgmt_cli/hitcount.sh ==================="
rm -f "$STUB_CAPTURE"
t 0 "default run (root, all domains)"    -- "$M" --local
has  "high-hit rule present"                "Allow-DNS"
has  "hit value rendered"                   "12345"
has  "zero-level shown"                     "zero"
has  "disabled rule marked"                 "(disabled)"
has  "footer totals"                        "7 rules shown (2 zero-hit) across 2 domain(s)"
has  "last-hit trimmed to date"             "2026-07-21"
if check_capture_window; then PASS=$((PASS+1)); echo "PASS capture  default window = today-182d .. today sent to API"
else FAIL=$((FAIL+1)); echo "FAIL capture  default window wrong: $(cat "$STUB_CAPTURE")"; fi

rm -f "$STUB_CAPTURE"
t 0 "--target forwarded"                 -- "$M" --local --target BigFW
if grep -q '"target": "BigFW"' "$STUB_CAPTURE"; then PASS=$((PASS+1)); echo "PASS capture  --target reached hits-settings"
else FAIL=$((FAIL+1)); echo "FAIL capture  target missing: $(cat "$STUB_CAPTURE")"; fi

t 0 "--zero-only lists the 2 unused"     -- "$M" --local --zero-only
has  "Block-Telnet listed"                  "Block-Telnet"
has  "Block-SMTP listed"                    "Block-SMTP"
has  "footer says 2"                        "2 rules shown (2 zero-hit)"
hasnt "no hit rules leak in"                "Allow-DNS"

t 0 "--min-hits 500 keeps 3"             -- "$M" --local --min-hits 500
has  "footer says 3"                        "3 rules shown (0 zero-hit)"
t 0 "--top 1 is the most-hit rule"       -- "$M" --local --top 1
has  "top rule"                             "12345"
has  "footer says 1"                        "1 rules shown"

t 0 "--domain CMA-UK only"               -- "$M" --local --domain CMA-UK
has  "UK layer"                             "Standard_UK Network"
hasnt "no France rows"                      "CMA-France"
t 1 "--domain unknown -> exit 1"         -- "$M" --local --domain CMA-NOPE
t 0 "--layer substring filter"           -- "$M" --local --layer France
has  "footer says 5"                        "5 rules shown"

t 0 "--json emits records"               -- "$M" --local --json
if printf '%s' "$LAST_OUT" | jq -e 'length == 7' >/dev/null 2>&1; then
    PASS=$((PASS+1)); echo "PASS output   JSON has 7 records"
else FAIL=$((FAIL+1)); echo "FAIL output   JSON shape wrong"; fi
t 2 "--min-hits 999999 -> exit 2"        -- "$M" --local --min-hits 999999
t 1 "bad --from -> exit 1"               -- "$M" --local --from 01-2026-99
t 1 "--from after --to -> exit 1"        -- "$M" --local --from 2026-06-01 --to 2026-01-01
t 1 "--zero-only + --min-hits rejected"  -- "$M" --local --zero-only --min-hits 5

t 0 "--user with env password"           -- env MGMT_CLI_PASSWORD=secret "$M" --user admin --top 1
hasnt "no TEST-VIOLATION (password never on argv)" "TEST-VIOLATION"
t 1 "wrong password fails"               -- env MGMT_CLI_PASSWORD=bad "$M" --user admin
t 0 "help exits 0"                       -- "$M" --help
hasnt "help has no leaked code"             "set -uo pipefail"

echo
echo "=================== clish/hitcount_clish.sh ==================="
rm -f "$STUB_CAPTURE"
t 0 "user auth, default run"             -- env MGMT_CLI_PASSWORD=secret "$C" --user admin
has  "high-hit rule present"                "Allow-DNS"
has  "footer totals"                        "7 rules shown (2 zero-hit) across 2 domain(s)"
if check_capture_window; then PASS=$((PASS+1)); echo "PASS capture  default window sent via clish transport"
else FAIL=$((FAIL+1)); echo "FAIL capture  clish window wrong: $(cat "$STUB_CAPTURE")"; fi

t 0 "--zero-only via clish"              -- env MGMT_CLI_PASSWORD=secret "$C" --user admin --zero-only
has  "footer says 2"                        "2 rules shown (2 zero-hit)"
t 0 "--domain CMA-UK via clish"          -- env MGMT_CLI_PASSWORD=secret "$C" --user admin --domain CMA-UK
hasnt "no France rows"                      "CMA-France"
t 2 "--json no matches -> exit 2"        -- env MGMT_CLI_PASSWORD=secret "$C" --user admin --json --min-hits 999999
t 1 "bad password -> exit 1"             -- env MGMT_CLI_PASSWORD=wrong "$C" --user admin
has  "clear error message"                  "login to management failed"
t 1 "api-key unsupported on this build"  -- "$C" --api-key TESTKEY
has  "api-key hint printed"                 "does not support 'mgmt login api-key'"
t 1 "missing auth mode -> error"         -- "$C"
t 0 "help exits 0"                       -- "$C" --help
hasnt "help has no leaked code"             "set -uo pipefail"

echo
echo "=============== standalone SMS mode (show domains is empty) ==============="
SMS_FIX="$TESTDIR/stubs/fixtures-sms.json"
t 0 "SMS: mgmt_cli treats box as single server" -- env HITS_FIXTURES="$SMS_FIX" "$M" --local
has  "fallback note printed"                "No domains found - treating as a single management server"
has  "rows labeled (local)"                 "(local)"
has  "footer counts one local domain"       "4 rules shown (1 zero-hit) across 1 domain(s)"
t 0 "SMS: --zero-only finds the unused rule" -- env HITS_FIXTURES="$SMS_FIX" "$M" --local --zero-only
has  "Block-Telnet listed"                  "Block-Telnet"
has  "footer says 1"                        "1 rules shown (1 zero-hit)"
t 0 "SMS: clish transport falls back too"   -- env HITS_FIXTURES="$SMS_FIX" MGMT_CLI_PASSWORD=secret "$C" --user admin
has  "fallback note via clish"              "No domains found"
has  "rows labeled (local) via clish"       "(local)"

rm -f "$STUB_CAPTURE"
echo
echo "==================== RESULT: $PASS passed, $FAIL failed ===================="
[ "$FAIL" -eq 0 ]
