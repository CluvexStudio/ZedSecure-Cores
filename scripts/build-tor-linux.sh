#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOR_VERSION="${TOR_VERSION:-0.4.9.13}"
OPENSSL_VERSION="${OPENSSL_VERSION:-3.6.5}"
LIBEVENT_VERSION="${LIBEVENT_VERSION:-2.1.12-stable}"
ZLIB_VERSION="${ZLIB_VERSION:-1.3.1}"
OUT="${OUT:-$ROOT/out/tor-linux}"
WORK="${WORK:-$ROOT/work/tor-linux}"
JOBS="${JOBS:-$(nproc)}"

prefix="$WORK/prefix"
rm -rf "$WORK/build" "$prefix"
mkdir -p "$WORK/src" "$WORK/build" "$prefix" "$OUT"
fetch() {
  [ -f "$WORK/src/$2" ] || curl -fsSL --retry 3 -o "$WORK/src/$2" "$1"
}
fetch "https://github.com/madler/zlib/releases/download/v$ZLIB_VERSION/zlib-$ZLIB_VERSION.tar.gz" "zlib.tar.gz"
fetch "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" "openssl.tar.gz"
fetch "https://github.com/libevent/libevent/releases/download/release-$LIBEVENT_VERSION/libevent-$LIBEVENT_VERSION.tar.gz" "libevent.tar.gz"
fetch "https://archive.torproject.org/tor-package-archive/tor-$TOR_VERSION.tar.gz" "tor.tar.gz"

build="$WORK/build"

tar -xzf "$WORK/src/zlib.tar.gz" -C "$build"
(cd "$build/zlib-$ZLIB_VERSION" &&
  CFLAGS="-O2 -fPIC" ./configure --static --prefix="$prefix" > "$build/zlib.log" 2>&1 &&
  make -j"$JOBS" >> "$build/zlib.log" 2>&1 &&
  make install >> "$build/zlib.log" 2>&1) || { tail -40 "$build/zlib.log"; exit 1; }

tar -xzf "$WORK/src/openssl.tar.gz" -C "$build"
(cd "$build/openssl-$OPENSSL_VERSION" &&
  ./config no-shared no-tests no-docs no-apps no-module --prefix="$prefix" --libdir=lib > "$build/openssl.log" 2>&1 &&
  make -j"$JOBS" build_libs >> "$build/openssl.log" 2>&1 &&
  make install_dev >> "$build/openssl.log" 2>&1) || { tail -40 "$build/openssl.log"; exit 1; }

tar -xzf "$WORK/src/libevent.tar.gz" -C "$build"
(cd "$build/libevent-$LIBEVENT_VERSION" &&
  ./configure --prefix="$prefix" --disable-shared --enable-static --disable-openssl \
    --disable-samples --disable-libevent-regress --disable-debug-mode > "$build/libevent.log" 2>&1 &&
  make -j"$JOBS" >> "$build/libevent.log" 2>&1 &&
  make install >> "$build/libevent.log" 2>&1) || { tail -40 "$build/libevent.log"; exit 1; }

tar -xzf "$WORK/src/tor.tar.gz" -C "$build"
(cd "$build/tor-$TOR_VERSION" &&
  ./configure \
    --enable-static-libevent --with-libevent-dir="$prefix" \
    --enable-static-openssl --with-openssl-dir="$prefix" \
    --enable-static-zlib --with-zlib-dir="$prefix" \
    --disable-asciidoc --disable-manpage --disable-html-manual --disable-unittests \
    --disable-module-relay --disable-module-dirauth \
    --disable-lzma --disable-zstd --disable-seccomp --disable-libscrypt --disable-systemd > "$build/tor.log" 2>&1 &&
  make -j"$JOBS" src/app/tor >> "$build/tor.log" 2>&1) || { tail -60 "$build/tor.log"; exit 1; }

cp "$build/tor-$TOR_VERSION/src/app/tor" "$OUT/tor"
strip "$OUT/tor"
ls -l "$OUT/tor"
