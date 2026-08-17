#!/usr/bin/env bash
# The writable home, and what persists across sessions.
#
# ~/.config, ~/.cache and ~/.local are tmpfs so each session starts clean; the
# selected agent's own state is bind-mounted over them so its login survives.
# The interaction of those two is what this checks -- a tmpfs mounted after the
# bind would silently discard everything the agent saved.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image

for dir in .config .cache .local; do
  out="$(sandbox_run -- bash -c "touch ~/$dir/probe && echo written")"
  assert_contains "$out" "written" "~/$dir is writable"
done

# A tmpfs home does not carry anything between sessions.
sandbox_run -- bash -c 'echo marker > ~/.cache/leak' >/dev/null
out="$(sandbox_run -- bash -c 'cat ~/.cache/leak 2>&1 || true')"
assert_not_contains "$out" "marker" "a second session's ~/.cache"

# The selected agent's state directory does persist, because it is a bind.
marker="persisted-$$"
sandbox_run opencode -- bash -c "mkdir -p ~/.config/opencode && echo $marker > ~/.config/opencode/probe" >/dev/null
out="$(sandbox_run opencode -- bash -c 'cat ~/.config/opencode/probe 2>&1 || true')"
assert_contains "$out" "$marker" "the agent's own state in a later session"
rm -f "$HOME/.config/opencode/probe"

# ...and only for the agent that was selected.
out="$(sandbox_run claude -- bash -c 'ls ~/.config/opencode 2>&1 || true')"
assert_not_contains "$out" "probe" "another agent's state directory"
