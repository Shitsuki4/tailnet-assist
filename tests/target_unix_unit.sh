#!/usr/bin/env bash
# Unit tests for the helpers in target/unix/tna-target.sh (Linux and macOS).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../target/unix/tna-target.sh
source "$ROOT/target/unix/tna-target.sh" __lib
set +e
failed=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; failed=$((failed+1)); fi; }

KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOd7kmdX0s1yX6WbqcvJ6oFqRk0zjYH7d7nU2c8gk1nL tna-operator:alice@pc'
check "valid pubkey" 'validate_pubkey "$KEY"'
check "reject option injection" '! validate_pubkey "command=\"x\" $KEY"'
check "reject newline" '! validate_pubkey "$(printf "ssh-ed25519 AAAA\nssh-rsa BBBB")"'
check "label sanitized" '[[ "$(sanitize_label "a b/c")" == "a-b-c" ]]'
check "expiry never" '[[ -z "$(expiry_stamp never)" ]]'
check "expiry 7d format" '[[ "$(expiry_stamp 7d)" =~ ^[0-9]{12}Z$ ]]'
check "expiry 7d is in 7 days" '[[ "$(expiry_stamp 7d)" > "$(date -u +%Y%m%d%H%M)" ]]'
check "expiry bad spec" '! expiry_stamp 7w >/dev/null'
LINE="$(build_key_line "$KEY" alice deadbeef '100.64.0.0/10,fd7a:115c:a1e0::/48' 202611101342Z)"
check "key line" '[[ "$LINE" == "restrict,pty,from=\"100.64.0.0/10,fd7a:115c:a1e0::/48\",expiry-time=\"202611101342Z\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOd7kmdX0s1yX6WbqcvJ6oFqRk0zjYH7d7nU2c8gk1nL tna:alice:deadbeef" ]]'
F="$(mktemp)"
printf 'ssh-ed25519 AAAAOTHER other@host\n%s\n%s\n' "$LINE" "$(build_key_line "$KEY" bob 0123abcd '' '')" > "$F"
check "remove by label" '[[ "$(remove_tna_lines "$F" bob)" == 1 ]]'
check "foreign key kept" 'grep -q "AAAAOTHER" "$F"'
check "remove all" '[[ "$(remove_tna_lines "$F")" == 1 ]]'
check "one line left" '[[ "$(wc -l < "$F" | tr -d " ")" == 1 ]]'
check "missing file" '[[ "$(remove_tna_lines "$F.nope")" == 0 ]]'
rm -f "$F"
check "b64url" '[[ "$(printf "??>" | b64url)" == "Pz8-" ]]'
check "json escape" '[[ "$(json_esc "a\"b\\c")" == "a\\\"b\\\\c" ]]'
if [[ $failed -gt 0 ]]; then echo "$failed test(s) failed"; exit 1; fi
echo "all unix unit tests passed"
