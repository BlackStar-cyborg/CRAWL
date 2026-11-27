#!/usr/bin/env bash
# pull-logs.sh - copy all logs from a node to this machine. Never deletes anything,
# locally or on the node. Run it regularly (e.g. daily) so a dead node loses little.
#
# Run on your laptop (WSL on Windows), from anywhere inside the repository:
#   bash pilot/node/pull-logs.sh n01              # -> <repo>/data/n01/logs/ and data/n01/journal/
#   bash pilot/node/pull-logs.sh n01 some/folder  # other destination for the web logs
#
# The SSH login journal (who logged in to the node, from where) is saved too, as a dated
# file, because the node's journal is not kept forever.

set -euo pipefail

NODE="${1:?usage: bash pilot/node/pull-logs.sh <ssh-alias> [dest]}"
NODE_ID="${NODE_ID:-${NODE#*@}}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEST="${2:-$REPO/data/$NODE_ID/logs}"
JOURNAL="$REPO/data/$NODE_ID/journal"

mkdir -p "$DEST"
# exit code 23/24 = some files unreadable/vanished (e.g. root-only files): warn, keep the rest
rc=0; rsync -az --no-perms "$NODE:/var/log/crawl/" "$DEST/" || rc=$?
case "$rc" in
  0) ;;
  23|24) echo "WARNING: some files could not be copied (rsync code $rc), the rest was pulled." ;;
  *) echo "ERROR: rsync failed with code $rc" >&2; exit "$rc" ;;
esac
echo "Pulled web logs to $DEST ($(du -sh "$DEST" | cut -f1))"

mkdir -p "$JOURNAL"
J="$JOURNAL/ssh-$(date -u +%Y%m%dT%H%MZ).log"
if ssh "$NODE" 'journalctl -u ssh -u ssh.socket -o short-iso --no-pager' > "$J" 2>/dev/null && [ -s "$J" ]; then
  echo "Saved SSH journal to $J"
else
  rm -f "$J" 2>/dev/null || true
  echo "WARNING: could not read the SSH journal (is your user in group adm? log out/in once after setup)."
fi
