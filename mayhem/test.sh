#!/usr/bin/env bash
#
# mayhem/test.sh - run NUT's own check programs (built by mayhem/build.sh) and assert on what they
# print, plus known-answer probes of the nutconf tool. Every assertion is on output values, so a
# no-op or exit(0) build fails: a silent program prints none of the lines expected below.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

TB="$SRC/mayhem/build-tests"
TT="$TB/tests"
passed=0
failed=0

ok()  { passed=$((passed + 1)); echo "ok   - $1"; }
bad() { failed=$((failed + 1)); echo "FAIL - $1"; }

# run <program> -> $out (stdout+stderr); a missing program is a build.sh bug, so fail loudly
run() {
  local prog="$1"
  if [ ! -x "$prog" ]; then
    out=""
    return 1
  fi
  out=$(cd "$(dirname "$prog")" && timeout 300 "./$(basename "$prog")" 2>&1)
}

# expect_line <name> <regex>: the last program output must contain a line matching the regex
expect_line() {
  if printf '%s\n' "$out" | grep -Eq -- "$2"; then ok "$1"; else bad "$1 (no line matching: $2)"; fi
}

# expect_count <name> <regex> <min>: at least <min> matching lines, and no line that says FAIL
expect_count() {
  local n
  n=$(printf '%s\n' "$out" | grep -Ec -- "$2")
  if [ "$n" -ge "$3" ] && ! printf '%s\n' "$out" | grep -Eq -- '(^|[^A-Za-z])(FAIL|not ok)'; then
    ok "$1 ($n matches)"
  else
    bad "$1 ($n matches of /$2/, need >= $3 and no FAIL)"
  fi
}

run "$TT/parseconf-test"
expect_line "parseconf-test: 23 cases, 0 failures" '^parseconf: 23 cases through line/file/char, boundary and encoder checks: 0 failures$'

run "$TT/getvaluetest"
expect_count "getvaluetest: HID GetValue/SetValue cases" ' PASS$' 41

run "$TT/getexponenttest-belkin-hid"
expect_count "getexponenttest-belkin-hid: exponent cases" ' PASS$' 15

run "$TT/fixreportdesctest-tripplite-hid"
expect_line "fixreportdesctest-tripplite-hid: 0 checks failed" '^OK: 0 check\(s\) failed$'

run "$TT/nutsnprintftest"
expect_count "nutsnprintftest: truncation semantics" '^PASS: ' 6

run "$TT/test_authconf"
expect_line "test_authconf: 12 sections parsed" '^ok 33 - parsed 12 sections'
expect_line "test_authconf: all passed" '^All tests passed!$'

run "$TT/statetest"
expect_line "statetest: 0 failures" '^State update tests: 0 failures$'

run "$TT/test_upsdconf"
expect_line "test_upsdconf: 343 checks, 0 failures" '^343 checks, 0 failures$'

run "$TT/upssched-list-timers-test"
expect_count "upssched-list-timers-test: timer listing" '^PASS: ' 4

run "$TT/nuttimetest"
expect_count "nuttimetest: time arithmetic" '\(OK\)' 3

run "$TT/cppunittest"
expect_line "cppunittest: nutconf/nutstream/nutipc units" '^OK \(36\)$'

# Known-answer probes of the nutconf tool (libnutconf writing and re-reading configuration files).
NUTCONF="$TB/tools/nutconf/nutconf"
conf=$(mktemp -d)
trap 'rm -rf "$conf"' EXIT

if [ -x "$NUTCONF" ]; then
  "$NUTCONF" --local "$conf" --set-mode netserver >/dev/null 2>&1
  mode=$("$NUTCONF" --local "$conf" --get-mode 2>/dev/null)
  [ "$mode" = "netserver" ] && ok "nutconf: set-mode/get-mode round trip" || bad "nutconf: get-mode returned '$mode', expected netserver"
  grep -qx 'MODE=netserver' "$conf/nut.conf" && ok "nutconf: nut.conf holds MODE=netserver" || bad "nutconf: nut.conf lacks MODE=netserver"

  "$NUTCONF" --local "$conf" --set-monitor myups localhost:3499 1 monuser secret primary >/dev/null 2>&1
  grep -qx 'MONITOR myups@localhost:3499 1 monuser secret primary' "$conf/upsmon.conf" \
    && ok "nutconf: upsmon.conf MONITOR line" || bad "nutconf: upsmon.conf MONITOR line missing"

  "$NUTCONF" --local "$conf" --add-listen 127.0.0.1 3499 >/dev/null 2>&1
  grep -qx 'LISTEN 127.0.0.1 3499' "$conf/upsd.conf" \
    && ok "nutconf: upsd.conf LISTEN line" || bad "nutconf: upsd.conf LISTEN line missing"

  "$NUTCONF" --local "$conf" --set-device dummy dummy-ups /tmp/x 'desc=A UPS' >/dev/null 2>&1
  if grep -qx 'desc = "A UPS"' <(tr -d '\t' < "$conf/ups.conf") \
     && grep -qx 'driver = dummy-ups' <(tr -d '\t' < "$conf/ups.conf") \
     && grep -qx '\[dummy\]' "$conf/ups.conf"; then
    ok "nutconf: ups.conf device section"
  else
    bad "nutconf: ups.conf device section wrong"
  fi

  printf 'MODE=netclient\n' > "$conf/nut.conf"
  mode=$("$NUTCONF" --local "$conf" --get-mode 2>/dev/null)
  [ "$mode" = "netclient" ] && ok "nutconf: parses a hand-written nut.conf" || bad "nutconf: parsed mode '$mode', expected netclient"
else
  bad "nutconf tool was not built"
fi

emit_ctrf "nut-check-programs" "$passed" "$failed"
