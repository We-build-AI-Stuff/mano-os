#!/bin/sh
# Untrusted CI fixture, invoked only inside the approved task sandbox.
[ "$(uname -s)" = Linux ] && [ "$(id -u)" != 0 ] &&
  [ "${MANO_REDTEAM_CI:-}" = granted-guest-fixture ] || exit 2
if printf 'attacker\n' 2>/dev/null > /etc/mano/human.uid; then
  printf 'POLICY_WRITE_SUCCEEDED\n'
  exit 71
fi
exec /usr/bin/python3 -c 'from attacks import exercise; exercise("malicious-shell")'
