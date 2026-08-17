#!/usr/bin/env bash
# Commit signing works through the relay, and the private key never enters
# the sandbox.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image
require_network
require_command gpg
gpg --list-secret-keys >/dev/null 2>&1 || skip "the host has no GnuPG secret keys"
[ -n "$(gpg --list-secret-keys --with-colons 2>/dev/null | grep '^sec')" ] \
  || skip "the host has no GnuPG secret keys"

ws="$(make_workspace)"
trap 'rm -rf "$ws"; cleanup_sandboxes' EXIT
cd "$ws" || exit 1

# Deliberately no [network] block at all, and no allowed_hosts on port 22:
# gpg has no destination of its own, so --gpg alone must be enough to sign.
# `allow_signing`/push authorization is a separate, host-scoped concern --
# see the SSH probe below, and tests/integration/acceptance/40-relay-ssh.sh.
git init --quiet .
git config user.email "test@example.com"
git config user.name "Test"

# Read back from the commit object rather than with --show-signature.
# Verifying is not something the relay can do: git writes the payload to a
# temp file and passes gpg the *path*, but gpg runs in the sidecar, which has
# its own /tmp. Signing works because it travels over stdin/stdout. A gpgsig
# header on the object is the thing being claimed anyway -- that the private
# key on the host signed a commit made inside the sandbox.
out="$(sandbox_run --workspace --proxy --gpg --ssh --git -- bash -c '
  git config --global --add safe.directory "$PWD"
  echo x > file && git add file
  git commit -S -q -m signed 2>&1 && git cat-file commit HEAD 2>&1
' || true)"
assert_contains "$out" "gpgsig" "a commit signed through the relay with no [network] block"
assert_contains "$out" "BEGIN PGP SIGNATURE" "the signature on the commit object"

# The same run's SSH push stays refused: signing and push are authorized
# independently, and only signing is unconditional on --gpg.
if [ -n "${SSH_AUTH_SOCK:-}" ] && ssh-add -l >/dev/null 2>&1; then
  out="$(sandbox_run --workspace --proxy --gpg --ssh --git -- \
    bash -c 'ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -T git@github.com 2>&1 || true')"
  assert_not_contains "$out" "successfully authenticated" \
    "an SSH probe with --gpg but no allowed_hosts :22 entry"
fi

# --gpg forwards the public keyring and the agent socket, not the secret keys.
out="$(sandbox_run --workspace --proxy --gpg -- bash -c '
  ls ~/.gnupg/private-keys-v1.d 2>&1 || echo ABSENT
')"
assert_contains "$out" "ABSENT" "the private key directory inside the sandbox"

# --gpg-private is the flag that does expose them, and it is not the default:
# a run that did not ask for it must not get them.
out="$(sandbox_run --workspace --proxy --gpg -- bash -c '
  gpg --export-secret-keys 2>&1 | head -c 200; echo
')"
assert_not_contains "$out" "PRIVATE KEY BLOCK" "an attempt to export secret keys"
