#!/bin/bash
# ============================================================================
# hitcount.sh - Report per-rule Access Policy HIT COUNTS across all Domains
#               (CMAs) of a Multi-Domain server, using the mgmt_cli tool.
#
# Run on the MDS in EXPERT mode. Default auth is login-as-root (no credentials).
# For every domain: discover access layers, pull each rulebase with hit
# counters (show access-rulebase ... show-hits true), flatten sections, and
# print one line per rule. --zero-only lists cleanup candidates.
#
# Time window: last 6 months (182 days) up to today by default.
#   --from YYYY-MM-DD   --to YYYY-MM-DD   --target <enforcing-fw>
#
# Auth (default: --local):
#   --local            mgmt_cli login -r true  (run on the MDS, no credentials)
#   --api-key KEY      Login with an API key
#   --user U [--password P]   Password prompts (or MGMT_CLI_PASSWORD); handed
#                      to mgmt_cli via the environment, never on a command line.
#
# Filters:
#   --domain NAME      Only this domain/CMA
#   --layer SUBSTR     Only access layers whose name contains SUBSTR
#   --zero-only        Only rules with 0 hits
#   --min-hits N       Only rules with at least N hits
#   --top N            The N most-hit rules (sorted by hits, descending)
#
# Options: -m ADDR  --port N  --json
# Exit codes: 0 = rules reported, 2 = nothing matched, 1 = error.
#
# Examples:
#   ./hitcount.sh --zero-only
#   ./hitcount.sh --from 2026-01-01 --to 2026-06-30 --domain CMA-EMEA
#   ./hitcount.sh --target fw-paris --top 10 --json
# ============================================================================
set -uo pipefail

PORT=443
MODE="local"          # local | apikey | user
API_KEY=""
USERNAME=""
PASSWORD=""
MGMT=""
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
        --local)     MODE="local" ;;
        --api-key)   MODE="apikey"; API_KEY="${2:-}"; shift ;;
        --user)      MODE="user"; USERNAME="${2:-}"; shift ;;
        --password)  PASSWORD="${2:-}"; shift ;;
        --from)      FROM="${2:-}"; shift ;;
        --to)        TO="${2:-}"; shift ;;
        --target)    TARGET="${2:-}"; shift ;;
        --domain)    DOMAIN_FILTER="${2:-}"; shift ;;
        --layer)     LAYER_FILTER="${2:-}"; shift ;;
        --zero-only) ZERO_ONLY=1 ;;
        --min-hits)  MIN_HITS="${2:-}"; shift ;;
        --top)       TOP="${2:-}"; shift ;;
        -m)          MGMT="${2:-}"; shift ;;
        --port)      PORT="${2:-443}"; shift ;;
        --json)      AS_JSON=1 ;;
        -h|--help)   usage; exit 0 ;;
        *)           echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

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

# prompt for password if needed
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

# --- login helpers ----------------------------------------------------------
login_domain() {   # $1 = domain name ("" for System Data / default)
    local d="$1"; local a=(login)
    case "$MODE" in
        local)  a+=(-r true) ;;
        apikey) a+=(api-key "$API_KEY") ;;
        user)   a+=(user "$USERNAME") ;;   # password via env, keeps it out of `ps`
    esac
    [ -n "$d" ]    && a+=(domain "$d")
    [ -n "$MGMT" ] && a+=(-m "$MGMT")
    a+=(--port "$PORT" --format json)
    if [ "$MODE" = "user" ]; then
        MGMT_CLI_PASSWORD="$PASSWORD" mgmt_cli "${a[@]}" 2>/dev/null
    else
        mgmt_cli "${a[@]}" 2>/dev/null
    fi
}
get_sid()    { login_domain "$1" | "$JQ" -r '.sid // empty'; }
api()        { local sid="$1"; shift; mgmt_cli "$@" --session-id "$sid" --port "$PORT" --format json 2>/dev/null; }
logout_sid() { mgmt_cli logout --session-id "$1" --port "$PORT" >/dev/null 2>&1 || true; }

TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT

paged_names() {  # $1 sid, $2.. show command words; prints .objects[].name
    local sid="$1"; shift
    local off=0 page to total
    while :; do
        page="$(api "$sid" "$@" limit 100 offset "$off")"
        [ -z "$page" ] && break
        echo "$page" | "$JQ" -r '(.["access-layers"] // .objects // [])[]?.name // empty' 2>/dev/null
        to="$(echo "$page"    | "$JQ" -r '.to // 0' 2>/dev/null)"
        total="$(echo "$page" | "$JQ" -r '.total // 0' 2>/dev/null)"
        [ -z "$to" ] && break
        [ "${to:-0}" -ge "${total:-0}" ] && break
        off="$to"
    done
}

search_domain() {  # $1 = domain ("" for local/SMS)
    local d="$1" sid layer off page to total
    sid="$(get_sid "$d")"
    if [ -z "$sid" ]; then echo "  ! login failed: ${d:-local}" >&2; return; fi
    while IFS= read -r layer; do
        [ -z "$layer" ] && continue
        if [ -n "$LAYER_FILTER" ]; then
            echo "$layer" | grep -qi -- "$LAYER_FILTER" || continue
        fi
        off=0
        while :; do
            local a=(show access-rulebase name "$layer" show-hits true
                     hits-settings.from-date "$FROM" hits-settings.to-date "$TO"
                     use-object-dictionary false details-level standard
                     limit 100 offset "$off")
            [ -n "$TARGET" ] && a+=(hits-settings.target "$TARGET")
            page="$(api "$sid" "${a[@]}")"
            [ -z "$page" ] && break
            echo "$page" | "$JQ" -c --arg domain "${d:-(local)}" --arg layer "$layer" \
                "$RULE_FILTER" >> "$TMP" 2>/dev/null
            to="$(echo "$page"    | "$JQ" -r '.to // 0' 2>/dev/null)"
            total="$(echo "$page" | "$JQ" -r '.total // 0' 2>/dev/null)"
            [ -z "$to" ] && break
            [ "${to:-0}" -ge "${total:-0}" ] && break
            off="$to"
        done
    done < <(paged_names "$sid" show access-layers details-level standard)
    logout_sid "$sid"
}

# --- enumerate domains ------------------------------------------------------
sid0="$(get_sid "")"
[ -z "$sid0" ] && { echo "ERROR: login to management failed." >&2; exit 1; }
DOMAINS=()
while IFS= read -r name; do [ -n "$name" ] && DOMAINS+=("$name"); done \
    < <(paged_names "$sid0" show domains details-level standard)
logout_sid "$sid0"

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
    search_domain ""
else
    for d in "${DOMAINS[@]}"; do search_domain "$d"; done
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
