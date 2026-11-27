#!/usr/bin/env bash
# deploy-site.sh - build the honeytoken site and put it live on a node.
#
# Run on your laptop (WSL on Windows), from anywhere inside the repository:
#   bash pilot/node/deploy-site.sh NODE BASE_URL DEPLOYMENT [CONTACT_EMAIL]
#   bash pilot/node/deploy-site.sh n01 https://example.ch n01-2026-12 you@uzh.ch
#
#   NODE        ssh host alias from ~/.ssh/config (also used as node id in the registry)
#   BASE_URL    the address written into the PDFs: https://<domain> once the certificate
#               exists, otherwise http://<domain> or http://<node-ip>
#   DEPLOYMENT  deployment window id. Same id = same tokens (re-deploy is safe).
#               A new id = new tokens; the node's previous tokens are marked retired.
#   CONTACT     optional, published in /.well-known/security.txt
#
# Steps: build -> pre-register (hash) -> upload -> mark exposed -> resolve one positive control.
# Registry and token secret stay in data/<node>/state on THIS machine (git-ignored).
# Back that folder up: without it, the tokens cannot be attributed any more.
#
# Environment: CONFIRM=yes skips the approval question, NODE_ID overrides the node id.

set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
NODE="${1:-}"; BASE_URL="${2:-}"; DEPLOYMENT="${3:-}"; CONTACT="${4:-}"
[ -n "$NODE" ] && [ -n "$BASE_URL" ] && [ -n "$DEPLOYMENT" ] || {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
NODE_ID="${NODE_ID:-$NODE}"
[[ "$NODE_ID" =~ ^[A-Za-z][A-Za-z0-9_-]*$ ]] || die "node id '$NODE_ID' should be an ssh alias like n01 (or set NODE_ID=n01)"
[[ "$DEPLOYMENT" =~ ^[A-Za-z0-9._-]+$ ]] || die "DEPLOYMENT may only contain letters, digits, . _ -"
[[ "$BASE_URL" =~ ^https?://[^/[:space:]]+$ ]] || die "BASE_URL must look like https://example.ch (no path, no trailing slash)"
# work from the repository root, wherever the script is called from
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
[ -f pilot/tools/build_site.py ] || die "pilot/tools/build_site.py not found in $REPO"
DATA="data/$NODE_ID"
if command -v git >/dev/null && git rev-parse --git-dir >/dev/null 2>&1; then
  git check-ignore -q "$DATA/state/registry.sqlite" || die "$DATA is not git-ignored - refusing to write secrets there"
fi
command -v python3 >/dev/null || die "python3 missing"
command -v rsync >/dev/null || die "rsync missing (sudo apt install rsync)"

echo "== Node check"
ssh "$NODE" 'test -w /var/www/crawl && test -f /etc/nginx/snippets/crawl-site.conf' \
  || die "$NODE: /var/www/crawl not writable or setup-node.sh (v2) not run yet"

if [ "${CONFIRM:-}" != yes ]; then
  echo
  echo "This puts honeytokens publicly online on $NODE ($BASE_URL), deployment $DEPLOYMENT."
  echo "Repo ground rule 3: nothing goes publicly online without supervisor approval."
  read -r -p "Approval obtained? Type yes to continue: " ans
  [ "$ans" = yes ] || die "aborted"
fi

echo "== Build"
python3 pilot/tools/build_site.py --out "$DATA/site" --state "$DATA/state" --node "$NODE_ID" \
  --deployment "$DEPLOYMENT" --base-url "$BASE_URL" ${CONTACT:+--contact "$CONTACT"}
mkdir -p "$DATA/site/.well-known"     # keeps the node's .well-known/acme-challenge/ in place

echo "== Pre-registration (do this before go-live; the hash can be shared, it reveals no tokens)"
python3 pilot/tools/registry.py --state "$DATA/state" prereg --node "$NODE_ID" --deployment "$DEPLOYMENT"

echo "== Upload"
rsync -rlptz --delete --chmod=D755,F644 \
  --exclude '/.well-known/acme-challenge/' --exclude '/.crawl-build' \
  "$DATA/site/" "$NODE:/var/www/crawl/"

echo "== Go-live time"
python3 pilot/tools/registry.py --state "$DATA/state" mark-exposed --node "$NODE_ID" --deployment "$DEPLOYMENT"

echo "== Our own address (as the node sees it) -> $DATA/internal_ips.txt"
MYIP="$(ssh "$NODE" 'echo "${SSH_CLIENT%% *}"' || true)"
touch "$DATA/internal_ips.txt"
if [ -n "$MYIP" ] && ! grep -qxF "$MYIP" <(sed 's/#.*//; s/[[:space:]]//g' "$DATA/internal_ips.txt"); then
  echo "$MYIP   # added by deploy-site.sh $(date -u +%Y-%m-%d)" >> "$DATA/internal_ips.txt"
fi
grep -qxF "127.0.0.1" <(sed 's/#.*//; s/[[:space:]]//g' "$DATA/internal_ips.txt") \
  || echo "127.0.0.1   # node self-tests" >> "$DATA/internal_ips.txt"

echo "== Positive control: resolving the first one now, from this machine"
mapfile -t POS < <(python3 pilot/tools/registry.py --state "$DATA/state" positive-urls --node "$NODE_ID" --deployment "$DEPLOYMENT")
if [ "${#POS[@]}" -gt 0 ]; then
  code="$(curl -s -o /dev/null -w '%{http_code}' -A "crawl-positive-control" "$BASE_URL${POS[0]}" || true)"
  echo "  $BASE_URL${POS[0]} -> HTTP $code"
  [ "$code" = 200 ] || echo "  WARNING: expected 200. Is $BASE_URL reachable from here?"
  for u in "${POS[@]:1}"; do echo "  kept for a later check (e.g. from your phone): $BASE_URL$u"; done
fi
robots="$(curl -s -m 10 "$BASE_URL/robots.txt" || true)"
if echo "$robots" | grep -q "Disallow: /archive/"; then echo "== Live: $BASE_URL/robots.txt serves the new site"
else echo "WARNING: $BASE_URL/robots.txt does not show the new site"; fi

echo
echo "Done. Registry: $REPO/$DATA/state (back it up, never commit it)."
echo "Check the pipeline: bash pilot/node/pull-logs.sh $NODE, then run the matcher (pilot/README.md)."
