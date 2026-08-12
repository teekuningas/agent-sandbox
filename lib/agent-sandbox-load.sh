#!/usr/bin/env bash
# Build the image and import it into the host's podman image store.
#
# streamLayeredImage writes the tar to stdout instead of materialising a
# multi-gigabyte tarball in the nix store first, so this pipes straight into
# podman load.

usage() {
  cat <<'USAGE'
Usage: agent-sandbox-ctl load

Builds the agent-sandbox image and imports it into podman.  Takes no options.
USAGE
}

# Worth handling explicitly: every other subcommand accepts -h, and without this
# `agent-sandbox-ctl load --help` would build and import the whole image.
case "${1:-}" in
  "")        ;;
  -h|--help) usage; exit 0 ;;
  *)         echo "agent-sandbox-load: unexpected argument: $1" >&2; usage >&2; exit 1 ;;
esac

echo "Loading $AGENT_SANDBOX_IMAGE into podman..."
"$AGENT_SANDBOX_IMAGE_STREAM" | podman load
echo "Done. Run 'agent-sandbox' to start a session."
