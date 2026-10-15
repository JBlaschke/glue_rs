#!/bin/sh
# Publish an evidence directory's bulk files as a GitHub release asset, keeping
# only README.md, inventories and bundle.json in the tree.
# See docs/decisions/0030-evidence-retention.md.
#
# usage: sh scripts/retain-evidence.sh docs/evidence/NAME [--publish] [--output DIR]
#
# Without --publish nothing in the tree changes: the inventory is verified,
# bundle-payload.sha256 is written to the output directory for inspection,
# the archive is packed there and its identity is printed.
set -eu

usage() {
  echo "usage: sh scripts/retain-evidence.sh docs/evidence/NAME [--publish] [--output DIR]" >&2
  exit 2
}
fail() {
  echo "retain-evidence: $*" >&2
  exit 1
}

dir=""
publish=0
output="target/evidence-bundles"
while [ $# -gt 0 ]; do
  case "$1" in
    --publish) publish=1 ;;
    --output)
      shift
      [ $# -gt 0 ] || usage
      output=$1
      ;;
    -h | --help) usage ;;
    -*) usage ;;
    *)
      [ -z "$dir" ] || usage
      dir=$1
      ;;
  esac
  shift
done
[ -n "$dir" ] || usage
dir=${dir%/}
[ -d "$dir" ] || fail "$dir is not a directory"
case "$dir" in
  docs/evidence/*) ;;
  *) fail "$dir must be a directory below docs/evidence, named from the repository root" ;;
esac
name=$(basename "$dir")
case "$name" in
  *[!A-Za-z0-9._-]* | .*) fail "evidence directory name must be [A-Za-z0-9._-]" ;;
esac
[ -f "$dir/README.md" ] || fail "$dir has no README.md"
[ ! -e "$dir/bundle.json" ] || fail "$dir already has bundle.json"
[ ! -e "$dir/bundle-payload.sha256" ] || fail "$dir already has bundle-payload.sha256"
git rev-parse --show-toplevel >/dev/null 2>&1 || fail "run from inside the repository"
[ "$(git rev-parse --show-toplevel)" = "$(pwd -P)" ] || fail "run from the repository root"

if command -v sha256sum >/dev/null 2>&1; then
  digest() { sha256sum "$@"; }
else
  digest() { shasum -a 256 "$@"; }
fi
check_inventory() {
  # $1: directory, $2: inventory file relative to it
  if ! out=$(cd "$1" && digest --check "$2" 2>&1); then
    echo "$out" | grep -v ': OK$' >&2 || true
    fail "inventory $2 does not match $1"
  fi
}

# The author's own inventory, when present, must hold before anything moves.
inventory=""
for candidate in artifacts.sha256 SHA256SUMS; do
  if [ -f "$dir/$candidate" ]; then
    inventory=$candidate
    break
  fi
done
if [ -n "$inventory" ]; then
  check_inventory "$dir" "$inventory"
  echo "verified $dir/$inventory"
else
  echo "note: $dir has no artifacts.sha256 or SHA256SUMS; bundle-payload.sha256 becomes its inventory" >&2
fi

mkdir -p "$output"
# Later steps change directory into the bundle, so the output must be absolute.
output=$(cd "$output" && pwd -P)
work="$output/$name.work"
rm -rf "${work:?}"
mkdir -p "$work"
list="$work/payload.txt"
# Payload: every file except the narrative, the inventories and bundle.json.
(cd "$dir" && find . -type f \
  ! -path ./README.md \
  ! -path ./bundle.json \
  ! -name '*.sha256' \
  ! -name 'SHA256SUMS*' |
  sed 's|^\./||' | LC_ALL=C sort) >"$list"
count=$(wc -l <"$list" | tr -d ' ')
[ "$count" -gt 0 ] || fail "$dir has no payload files to publish"
if grep -q '[^ -~]' "$list"; then
  fail "payload file names must be printable ASCII"
fi

payload_inventory="$work/bundle-payload.sha256"
(cd "$dir" && while IFS= read -r file; do digest "$file"; done <"$list") >"$payload_inventory"

archive="$output/$name.tar.gz"
rm -f "${archive:?}"
# gzip -n omits the timestamp; the sorted list fixes member order.
tar -cf - -C "$dir" -T "$list" | gzip -n -9 >"$archive"
size=$(wc -c <"$archive" | tr -d ' ')
sha=$(digest "$archive" | cut -d' ' -f1)
tag="evidence/$name"
asset="$name.tar.gz"
repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null || echo "")
[ -n "$repo" ] || fail "gh cannot resolve the repository; authenticate with gh auth login"

printf 'payload files: %s\narchive: %s\nsize: %s\nsha256: %s\ntag: %s\nasset: %s\nrepository: %s\n' \
  "$count" "$archive" "$size" "$sha" "$tag" "$asset" "$repo"

if [ "$publish" -eq 0 ]; then
  echo "dry run: no release created and $dir unchanged; rerun with --publish"
  exit 0
fi

if gh release view "$tag" >/dev/null 2>&1; then
  fail "release $tag already exists; choose a new evidence directory name"
fi
# The release tag points at the commit being published from, which must
# already be on the remote; it is the commit whose README describes the bundle.
commit=$(git rev-parse HEAD)
git fetch -q origin "$commit" 2>/dev/null || git branch -r --contains "$commit" | grep -q . ||
  fail "commit $commit is not on the remote; push it before publishing"
notes="$work/notes.md"
{
  echo "Evidence bundle for \`$dir\`."
  echo
  echo "Published by scripts/retain-evidence.sh; see docs/decisions/0030-evidence-retention.md."
  echo "Fetch and verify with: sh scripts/fetch-evidence.sh $dir"
  echo
  echo "- commit: $commit"
  echo "- files: $count"
  echo "- size: $size bytes"
  echo "- sha256: $sha"
} >"$notes"
gh release create "$tag" "$archive#$asset" --title "Evidence: $name" --notes-file "$notes" \
  --target "$commit" --latest=false >/dev/null
echo "created release $tag at $commit with asset $asset"

cp "$payload_inventory" "$dir/bundle-payload.sha256"
published=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cat >"$dir/bundle.json" <<JSON
{
  "schema": "glue-evidence-bundle-1",
  "name": "$name",
  "repository": "$repo",
  "tag": "$tag",
  "commit": "$commit",
  "asset": "$asset",
  "size": $size,
  "sha256": "$sha",
  "files": $count,
  "published": "$published",
  "fetch": "sh scripts/fetch-evidence.sh $dir"
}
JSON
while IFS= read -r file; do
  if git ls-files --error-unmatch -- "$dir/$file" >/dev/null 2>&1; then
    git rm -q -- "${dir:?}/${file:?}"
  else
    rm -f -- "${dir:?}/${file:?}"
  fi
done <"$list"
find "${dir:?}" -type d -empty -delete
rm -rf "${work:?}"
echo "removed $count payload files from $dir; commit $dir/bundle.json and $dir/bundle-payload.sha256"
