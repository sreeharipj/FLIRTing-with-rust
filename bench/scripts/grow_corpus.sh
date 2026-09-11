#!/usr/bin/env bash
# round8 -- grow the rustsig donor corpus via `cargo install`, debug info kept.
#
# round40/round8 both found donor BREADTH is the mechanism behind both coverage
# and (newly, round8) cross-corpus naming precision. 32 donors already indexed
# (unhusk's realval/corpus_src); this adds RIFT's curated 80-crate list (minus
# anything already a donor, minus zellij -- zellij is a held-out cross-corpus
# TEST target and must never enter the donor set, or the precision numbers in
# round8 stop meaning anything).
#
# cargo install normally strips debug info per-crate profile settings; the
# CARGO_PROFILE_RELEASE_* env overrides below force debug info on and strip
# off regardless of what the crate's own Cargo.toml says (same knobs unhusk's
# build_corpus_src.sh uses).
set -u

OUT="${1:-./corpus_grow}"
TARGETS="${2:-./grow_targets.txt}"
export OUT
mkdir -p "$OUT"

export CARGO_PROFILE_RELEASE_DEBUG=true
export CARGO_PROFILE_RELEASE_STRIP=false
export CARGO_TERM_COLOR=never
export CARGO_NET_GIT_FETCH_WITH_CLI=true

build_one() {
  local crate="$1" bin="$2"
  local log="$OUT/$crate.build.log"
  if [ -f "$OUT/$crate.stripped" ] && [ -f "$OUT/$crate.debug" ]; then
    echo ">>> $crate: already built, skipping"
    return 0
  fi
  local root="$OUT/.install-$crate"
  rm -rf "$root"
  echo ">>> $crate: installing ($(date +%H:%M:%S))"
  if ! timeout 1800 cargo install --root "$root" --locked "$crate" >"$log" 2>&1; then
    if ! timeout 1800 cargo install --root "$root" "$crate" >>"$log" 2>&1; then
      echo "!!! $crate: INSTALL FAILED (see $log)"
      echo "INSTALL_FAILED" > "$OUT/$crate.FAILED"
      rm -rf "$root"
      return 1
    fi
  fi
  local built="$root/bin/$bin"
  if [ ! -f "$built" ]; then
    built=$(find "$root/bin" -maxdepth 1 -type f -perm -u+x 2>/dev/null | head -1)
  fi
  if [ ! -f "$built" ]; then
    echo "!!! $crate: binary '$bin' not found under $root/bin"
    echo "BIN_NOT_FOUND" > "$OUT/$crate.FAILED"
    rm -rf "$root"
    return 1
  fi
  cp "$built" "$OUT/$crate.debug"
  objcopy --strip-all "$OUT/$crate.debug" "$OUT/$crate.stripped" 2>>"$log"
  rm -rf "$root"
  if [ -f "$OUT/$crate.stripped" ]; then
    echo "    $crate: OK  debug=$(stat -c%s "$OUT/$crate.debug")  stripped=$(stat -c%s "$OUT/$crate.stripped")"
  else
    echo "!!! $crate: strip failed"
    echo "STRIP_FAILED" > "$OUT/$crate.FAILED"
  fi
}
export -f build_one

echo "=== corpus grow start $(date -Is) -> $OUT"
tail -n +2 "$TARGETS" | sed 's/|/ /' | \
  xargs -P 6 -L 1 bash -c 'build_one "$@"' _

echo "=== corpus grow done $(date -Is): $(ls "$OUT"/*.stripped 2>/dev/null | wc -l) stripped, $(ls "$OUT"/*.FAILED 2>/dev/null | wc -l) failed"
touch "$OUT/GROW_DONE"
