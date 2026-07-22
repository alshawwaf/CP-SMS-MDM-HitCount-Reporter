#!/bin/bash
# ============================================================================
# hitcount_clish.sh - Report per-rule Access Policy HIT COUNTS across all
#                     Domains (CMAs) of a Multi-Domain server, using Gaia
#                     Clish management commands ("mgmt login" / "mgmt show").
#
# A clish 'mgmt' session does not survive the clish process, clish ignores
# piped stdin, and the Management API scopes a session to ONE domain at login
# (verified on R82.10). So every API call runs login + command + logout as a
# clish batch file ('clish -i -f <file>'): a private 0600 temp file written
# and deleted per call. Credentials never appear in the process list.
# The script itself is bash, so it runs from EXPERT mode.
#
# Time window: last 6 months (182 days) up to today by default.
#   --from YYYY-MM-DD   --to YYYY-MM-DD   --target <enforcing-fw>
#
# Auth (one of):
#   --user U [--password P]  Log in as administrator U. The password is asked
#                            once (or read from MGMT_CLI_PASSWORD).
#   --api-key KEY            Only on Gaia builds whose clish supports api-key
#                            login (R82.10 clish does not; the script detects
#                            this and says so).
#
# Filters:
#   --domain NAME      Only this domain/CMA
#   --layer SUBSTR     Only access layers whose name contains SUBSTR
#   --zero-only        Only rules with 0 hits
#   --min-hits N       Only rules with at least N hits
#   --top N            The N most-hit rules (sorted by hits, descending)
#
# Options: --json
# Exit codes: 0 = rules reported, 2 = nothing matched, 1 = error.
#
# Examples:
#   ./hitcount_clish.sh --user admin --zero-only
#   ./hitcount_clish.sh --user admin --from 2026-01-01 --domain CMA-EMEA --json
# ============================================================================
set -uo pipefail

MODE=""               # user | apikey
USERNAME=""
API_KEY=""
PASSWORD=""
FROM=""
TO=""
TARGET=""
DOMAIN_FILTER=""
LAYER_FILTER=""
ZERO_ONLY=0
MIN_HITS=""
TOP=""
AS_JSON=0

# --- locate jq --------------------------------------------------------------
JQ="$(command -v jq 2>/dev/null || true)"
[ -z "$JQ" ] && [ -n "${CPDIR:-}" ] && JQ="$CPDIR/jq/jq"
if [ -z "$JQ" ] || [ ! -x "$JQ" ]; then
    echo "ERROR: jq not found (looked in PATH and \$CPDIR/jq/jq)." >&2
    exit 1
fi

usage() { sed -n '2,/^# ====/p' "$0" | sed 's/^# \{0,1\}//'; }

# --- argument parsing -------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --user)      MODE="user"; USERNAME="${2:-}"; shift ;;
        --password)  PASSWORD="${2:-}"; shift ;;
        --api-key)   MODE="apikey"; API_KEY="${2:-}"; shift ;;
        --from)      FROM="${2:-}"; shift ;;
        --to)        TO="${2:-}"; shift ;;
        --target)    TARGET="${2:-}"; shift ;;
        --domain)    DOMAIN_FILTER="${2:-}"; shift ;;
        --layer)     LAYER_FILTER="${2:-}"; shift ;;
        --zero-only) ZERO_ONLY=1 ;;
        --min-hits)  MIN_HITS="${2:-}"; shift ;;
        --top)       TOP="${2:-}"; shift ;;
        --json)      AS_JSON=1 ;;
        -h|--help)   usage; exit 0 ;;
        *)           echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

if [ -z "$MODE" ]; then
    echo "ERROR: choose an auth mode: --user U or --api-key KEY." >&2
    exit 1
fi

# --- time window (default: last 182 days ~ 6 months) ------------------------
datecheck() { echo "$1" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'; }
[ -z "$TO" ]   && TO="$(date +%F)"
if [ -z "$FROM" ]; then
    FROM="$(date -d '-182 days' +%F 2>/dev/null || date -v-182d +%F)"
fi
if ! datecheck "$FROM" || ! datecheck "$TO"; then
    echo "ERROR: --from/--to must be YYYY-MM-DD (got '$FROM' .. '$TO')." >&2
    exit 1
fi
if [ "$FROM" \> "$TO" ]; then
    echo "ERROR: --from ($FROM) is after --to ($TO)." >&2
    exit 1
fi
if [ "$ZERO_ONLY" = 1 ] && [ -n "$MIN_HITS" ]; then
    echo "ERROR: --zero-only and --min-hits are mutually exclusive." >&2
    exit 1
fi

# prompt for the password once if needed
if [ "$MODE" = "user" ] && [ -z "$PASSWORD" ]; then
    PASSWORD="${MGMT_CLI_PASSWORD:-}"
    if [ -z "$PASSWORD" ]; then
        read -rs -p "Password for $USERNAME: " PASSWORD; echo
    fi
fi

# --- jq: flatten rulebase page into per-rule records -------------------------
read -r -d '' RULE_FILTER <<'JQEOF'
.rulebase[]?
| (if .type == "access-section"
     then (.name // "") as $sec | ((.rulebase // [])[] | . + {__section: $sec})
     else . + {__section: ""} end)
| select(.type == "access-rule")
| {
    domain: $domain,
    layer: $layer,
    section: .__section,
    number: (.["rule-number"] // null),
    uid: .uid,
    name: (.name // "(unnamed)"),
    action: (if (.action | type) == "object" then (.action.name // "-")
             else ((.action // "-") | tostring) end),
    enabled: (.enabled != false),
    hits: (.hits.value // 0),
    level: (.hits.level // "zero"),
    percentage: (.hits.percentage // ""),
    first_hit: (.hits["first-date"]["iso-8601"]? // ""),
    last_hit: (.hits["last-date"]["iso-8601"]? // "")
  }
JQEOF

# --- clish transport --------------------------------------------------------
esc() { printf '%s' "$1" | sed 's/"/\\"/g'; }

extract_json() {  # stdin: raw clish output -> first balanced JSON document
    local block
    block="$(awk '
        BEGIN { f = 0; d = 0 }
        {
            if (!f) { t = $0; sub(/^[ \t]+/, "", t); if (t ~ /^\{/) f = 1; else next }
            print
            n = gsub(/{/, "{"); m = gsub(/}/, "}")
            d += n - m
            if (d <= 0) exit
        }')"
    if [ -n "$block" ] && printf '%s' "$block" | "$JQ" -e . >/dev/null 2>&1; then
        printf '%s\n' "$block"; return 0
    fi
    return 1
}

clish_api() {  # $1 = domain ("" = MDS/System Data), $2 = full mgmt command
               # stdout: JSON document; rc: 0 ok, 2 login failed, 1 other error
    local d="$1" cmd="$2" login f raw
    case "$MODE" in
        user)   login="mgmt login user \"$(esc "$USERNAME")\" password \"$(esc "$PASSWORD")\"" ;;
        apikey) login="mgmt login api-key \"$(esc "$API_KEY")\"" ;;
    esac
    [ -n "$d" ] && login="$login domain \"$(esc "$d")\""
    f="$(mktemp)"
    chmod 600 "$f"
    printf '%s\n%s\nmgmt logout\n' "$login" "$cmd" > "$f"
    raw="$(clish -i -f "$f" 2>/dev/null | tr -d '\r' \
           | sed 's/Processing line [0-9][0-9]* out of [0-9][0-9]*//g')"
    rm -f "$f"
    if printf '%s' "$raw" | grep -q 'CLINFR'; then
        if [ "$MODE" = "apikey" ]; then
            echo "ERROR: this Gaia build's clish does not support 'mgmt login api-key' - use --user instead." >&2
        fi
        return 1
    fi
    if printf '%s' "$raw" | grep -qE 'err_login_failed|MGMT9000'; then
        return 2
    fi
    printf '%s\n' "$raw" | extract_json
}

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

paged_names() {  # $1 domain, $2 object kind (domains|access-layers)
    local d="$1" kind="$2" off=0 page to total
    while :; do
        page="$(clish_api "$d" "mgmt show $kind details-level standard limit 100 offset $off --format json")"
        [ $? -ne 0 ] && break
        [ -z "$page" ] && break
        echo "$page" | "$JQ" -r '(.["access-layers"] // .objects // [])[]?.name // empty' 2>/dev/null
        to="$(echo "$page"    | "$JQ" -r '.to // 0' 2>/dev/null)"
        total="$(echo "$page" | "$JQ" -r '.total // 0' 2>/dev/null)"
        [ -z "$to" ] && break
        [ "${to:-0}" -ge "${total:-0}" ] && break
        off="$to"
    done
}

search_domain() {  # $1 = domain ("" for SMS/local), $2 = record label
    local d="$1" label="$2" layer off page to total rc
    while IFS= read -r layer; do
        [ -z "$layer" ] && continue
        if [ -n "$LAYER_FILTER" ]; then
            echo "$layer" | grep -qi -- "$LAYER_FILTER" || continue
        fi
        off=0
        while :; do
            local cmd="mgmt show access-rulebase name \"$(esc "$layer")\" show-hits true hits-settings.from-date \"$FROM\" hits-settings.to-date \"$TO\""
            [ -n "$TARGET" ] && cmd="$cmd hits-settings.target \"$(esc "$TARGET")\""
            cmd="$cmd use-object-dictionary false details-level standard limit 100 offset $off --format json"
            page="$(clish_api "$d" "$cmd")"
            rc=$?
            if [ $rc -eq 2 ]; then echo "  ! login failed: ${label}" >&2; return; fi
            [ -z "$page" ] && break
            echo "$page" | "$JQ" -c --arg domain "$label" --arg layer "$layer" \
                "$RULE_FILTER" >> "$TMP" 2>/dev/null
            to="$(echo "$page"    | "$JQ" -r '.to // 0' 2>/dev/null)"
            total="$(echo "$page" | "$JQ" -r '.total // 0' 2>/dev/null)"
            [ -z "$to" ] && break
            [ "${to:-0}" -ge "${total:-0}" ] && break
            off="$to"
        done
    done < <(paged_names "$d" access-layers)
}

# --- run --------------------------------------------------------------------
# enumerate domains from the MDS (System Data) context; also validates login
DOMAINS=()
off=0
while :; do
    DJ="$(clish_api "" "mgmt show domains details-level standard limit 100 offset $off --format json")"
    rc=$?
    if [ $rc -eq 2 ]; then
        echo "ERROR: login to management failed (check credentials and 'api status')." >&2
        exit 1
    fi
    if [ $rc -eq 1 ] && [ "$MODE" = "apikey" ]; then
        exit 1
    fi
    [ -z "$DJ" ] && break
    while IFS= read -r name; do [ -n "$name" ] && DOMAINS+=("$name"); done \
        < <(echo "$DJ" | "$JQ" -r '.objects[]?.name // empty' 2>/dev/null)
    to="$(echo "$DJ"    | "$JQ" -r '.to // 0' 2>/dev/null)"
    total="$(echo "$DJ" | "$JQ" -r '.total // 0' 2>/dev/null)"
    [ -z "$to" ] && break
    [ "${to:-0}" -ge "${total:-0}" ] && break
    off="$to"
done

if [ -n "$DOMAIN_FILTER" ]; then
    FOUND=""
    for d in "${DOMAINS[@]:-}"; do
        [ "$(echo "$d" | tr '[:upper:]' '[:lower:]')" = \
          "$(echo "$DOMAIN_FILTER" | tr '[:upper:]' '[:lower:]')" ] && FOUND="$d"
    done
    if [ -z "$FOUND" ]; then
        echo "ERROR: domain '$DOMAIN_FILTER' not found." >&2
        exit 1
    fi
    DOMAINS=("$FOUND")
fi

if [ "${#DOMAINS[@]}" -eq 0 ]; then
    echo "# No domains found - treating as a single management server." >&2
    search_domain "" "(local)"
else
    for d in "${DOMAINS[@]}"; do search_domain "$d" "$d"; done
fi

# --- filters + render --------------------------------------------------------
FILTER='.'
[ "$ZERO_ONLY" = 1 ] && FILTER="$FILTER | map(select(.hits == 0))"
[ -n "$MIN_HITS" ]   && FILTER="$FILTER | map(select(.hits >= ${MIN_HITS}))"
[ -n "$TOP" ]        && FILTER="$FILTER | sort_by(-.hits) | .[0:${TOP}]"

ARR="$("$JQ" -s "$FILTER" "$TMP" 2>/dev/null)"
[ -z "$ARR" ] && ARR="[]"
COUNT="$(echo "$ARR" | "$JQ" 'length')"

if [ "$AS_JSON" = 1 ]; then
    echo "$ARR"
    [ "${COUNT:-0}" -gt 0 ] && exit 0
    exit 2
fi

if [ "${COUNT:-0}" -eq 0 ]; then
    echo "No rules matched the filters (window $FROM .. $TO)."
    exit 2
fi

{
    printf 'DOMAIN(CMA)\tLAYER\tNO\tRULE\tACTION\tHITS\tLEVEL\tLAST HIT\n'
    echo "$ARR" | "$JQ" -r '.[] |
        [ .domain, .layer, (.number // "-"),
          (.name + (if .enabled then "" else "  (disabled)" end)),
          .action, .hits, .level,
          (if (.last_hit // "") != "" then (.last_hit | .[0:10]) else "-" end) ]
        | @tsv'
} | column -t -s "$(printf '\t')"
echo
ZERO="$(echo "$ARR" | "$JQ" '[.[] | select(.hits == 0)] | length')"
NDOM="$(echo "$ARR" | "$JQ" '[.[].domain] | unique | length')"
echo "$COUNT rules shown ($ZERO zero-hit) across $NDOM domain(s) | window: $FROM .. $TO"
