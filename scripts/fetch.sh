#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
wanted="$*"
while read -r path url rev; do
  case "$path" in ''|\#*) continue ;; esac
  if [ -n "$wanted" ]; then
    keep=0
    for w in $wanted; do [ "$w" = "$path" ] && keep=1; done
    [ "$keep" = 1 ] || continue
  fi
  dest="$ROOT/$path"
  if [ -d "$dest/.git" ] && [ "$(git -C "$dest" rev-parse HEAD)" = "$rev" ]; then
    echo "== $path already at $rev"
    continue
  fi
  echo "== $path <- $url @ $rev"
  rm -rf "$dest"
  mkdir -p "$(dirname "$dest")"
  git clone -q --filter=blob:none "$url" "$dest"
  git -C "$dest" checkout -q "$rev"
done < "$ROOT/pins.txt"
