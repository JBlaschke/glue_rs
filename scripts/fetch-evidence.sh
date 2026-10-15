#!/bin/sh
# Restore a published evidence bundle next to its committed README and verify
# every file against the committed inventories.
# See docs/decisions/0030-evidence-retention.md.
#
# usage: sh scripts/fetch-evidence.sh docs/evidence/NAME
set -eu

fail() {
  echo "fetch-evidence: $*" >&2
  exit 1
}
[ $# -eq 1 ] || {
  echo "usage: sh scripts/fetch-evidence.sh docs/evidence/NAME" >&2
  exit 2
}
dir=${1%/}
[ -f "$dir/bundle.json" ] || fail "$dir has no bundle.json"
[ -f "$dir/bundle-payload.sha256" ] || fail "$dir has no bundle-payload.sha256"

field() {
  sed -n "s/^ *\"$1\": *\"\{0,1\}\([^\",]*\)\"\{0,1\},\{0,1\}\$/\1/p" "$dir/bundle.json" | head -n 1
}
tag=$(field tag)
asset=$(field asset)
sha=$(field sha256)
size=$(field size)
repo=$(field repository)
[ -n "$tag" ] && [ -n "$asset" ] && [ -n "$sha" ] && [ -n "$size" ] && [ -n "$repo" ] || fail "bundle.json is incomplete"
case "$asset" in
  *[!A-Za-z0-9._-]* | .*) fail "asset name in bundle.json is not plain" ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
  digest() { sha256sum "$@"; }
else
  digest() { shasum -a 256 "$@"; }
fi
check_inventory() {
  if ! out=$(cd "$dir" && digest --check "$1" 2>&1); then
    echo "$out" | grep -v ': OK$' >&2 || true
    fail "inventory $1 does not match $dir"
  fi
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/glue-evidence.XXXXXX")
trap 'rm -rf "${tmp:?}"' EXIT
gh release download "$tag" --repo "$repo" --pattern "$asset" --dir "$tmp" >/dev/null
[ -f "$tmp/$asset" ] || fail "release $tag has no asset $asset"
actual_size=$(wc -c <"$tmp/$asset" | tr -d ' ')
[ "$actual_size" = "$size" ] || fail "asset size $actual_size differs from recorded $size"
actual=$(digest "$tmp/$asset" | cut -d' ' -f1)
[ "$actual" = "$sha" ] || fail "asset sha256 $actual differs from recorded $sha; the release asset is not the committed bundle"

# Refuse archive members that could escape or replace the committed files.
if tar -tzf "$tmp/$asset" | grep -E '^(/|\.\./|.*/\.\./)|^(README\.md|bundle\.json|bundle-payload\.sha256)$' >/dev/null; then
  fail "archive contains an escaping or reserved member"
fi
tar -xzf "$tmp/$asset" -C "$dir"
check_inventory bundle-payload.sha256
for candidate in artifacts.sha256 SHA256SUMS; do
  if [ -f "$dir/$candidate" ]; then
    check_inventory "$candidate"
    echo "verified $dir/$candidate"
    break
  fi
done
echo "restored and verified $dir from release $tag"
