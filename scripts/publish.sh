#!/usr/bin/env bash
set -euo pipefail
tag="${1:?release tag}"
dir="${2:?directory with the files}"
cd "$dir"
rm -f SHA256SUMS
sha256sum -- * > SHA256SUMS
cat SHA256SUMS
if gh release view "$tag" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
  gh release upload "$tag" --repo "$GITHUB_REPOSITORY" --clobber ./*
else
  gh release create "$tag" --repo "$GITHUB_REPOSITORY" --title "$tag" \
    --notes "built from ${GITHUB_SHA:0:7}" --latest=false ./*
fi
