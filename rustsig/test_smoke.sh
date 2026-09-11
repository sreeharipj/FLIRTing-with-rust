#!/usr/bin/env bash
# Minimal regression check: build a DB from a couple of donor binaries, label
# a held-out stripped target, assert coverage/precision don't fall off a
# cliff. Not a substitute for the real evaluation harness in bench/ -- this is a
# "did I just break the tool" smoke test, meant to run in seconds.
set -euo pipefail
cd "$(dirname "$0")"

CORPUS=${RUSTSIG_CORPUS:-}
[ -f "$CORPUS/bat.debug" ] || { echo "SKIP: donor corpus not present at $CORPUS"; exit 0; }

DB=$(mktemp /tmp/rustsig_smoke_XXXX.json)
trap 'rm -f "$DB"' EXIT

echo "-- build --"
python3 rustsig.py build "$DB" "$CORPUS/bat.debug" "$CORPUS/ripgrep.debug" "$CORPUS/fd.debug"

echo "-- label (target: dust, not a donor) --"
OUT=$(python3 rustsig.py label "$DB" "$CORPUS/dust.stripped" --json --min-confidence 1)
n_labeled=$(echo "$OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['n_labeled'])")
n_functions=$(echo "$OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['n_functions'])")

echo "labeled $n_labeled / $n_functions"
if [ "$n_labeled" -lt 500 ]; then
  echo "FAIL: expected >=500 labeled functions from a 3-crate donor set, got $n_labeled"
  exit 1
fi

echo "-- min-confidence filter reduces coverage (sanity: filter actually filters) --"
OUT2=$(python3 rustsig.py label "$DB" "$CORPUS/dust.stripped" --json --min-confidence 3)
n_labeled2=$(echo "$OUT2" | python3 -c "import json,sys; print(json.load(sys.stdin)['n_labeled'])")
if [ "$n_labeled2" -gt "$n_labeled" ]; then
  echo "FAIL: --min-confidence 3 labeled more than --min-confidence 1 ($n_labeled2 > $n_labeled)"
  exit 1
fi

echo "OK: $n_labeled labeled at min-confidence=1, $n_labeled2 at min-confidence=3"

SHIPPED_DB=db/std_and_common_x86_64.json.gz
if [ -f "$SHIPPED_DB" ]; then
  echo "-- shipped DB loads and labels (gzip transparency check) --"
  OUT3=$(python3 rustsig.py label "$SHIPPED_DB" "$CORPUS/dust.stripped" --json)
  n_labeled3=$(echo "$OUT3" | python3 -c "import json,sys; print(json.load(sys.stdin)['n_labeled'])")
  echo "OK: shipped DB labeled $n_labeled3 functions in dust.stripped"
else
  echo "SKIP: shipped DB not present at $SHIPPED_DB"
fi

UNHUSK_BIN=${UNHUSK_BIN:-unhusk}
if [ -f "$UNHUSK_BIN" ] && [ -f "$SHIPPED_DB" ]; then
  echo "-- triage.py combines rustsig + unhusk --"
  TOUT=$(python3 triage.py "$CORPUS/dust.stripped" --rustsig-db "$SHIPPED_DB" \
         --unhusk-bin "$UNHUSK_BIN" --json)
  n_author=$(echo "$TOUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['counts']['AUTHOR'])")
  n_library=$(echo "$TOUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['counts']['LIBRARY'])")
  if [ "$n_author" -lt 1 ] || [ "$n_library" -lt 1 ]; then
    echo "FAIL: triage.py found AUTHOR=$n_author LIBRARY=$n_library, expected both >0 on dust"
    exit 1
  fi
  echo "OK: triage.py found AUTHOR=$n_author LIBRARY=$n_library"

  echo "-- triage.py bucket accounting (every function lands in exactly one bucket) --"
  echo "$TOUT" | python3 -c '
import json, sys
r = json.load(sys.stdin)
c, n = r["counts"], r["n_functions"]
buckets = ("AUTHOR", "LIBRARY", "UNKNOWN", "UNDECODABLE")
missing = [b for b in buckets if b not in c]
if missing:
    sys.exit("FAIL: counts missing bucket(s): %s" % ", ".join(missing))
total = sum(c[b] for b in buckets)
if total != n:
    sys.exit("FAIL: buckets sum to %d, n_functions is %d" % (total, n))
if r["n_decodable"] != n - c["UNDECODABLE"]:
    sys.exit("FAIL: n_decodable %d != n_functions %d - UNDECODABLE %d"
             % (r["n_decodable"], n, c["UNDECODABLE"]))
# UNDECODABLE rows must carry a reason, and must never be author- or DB-named
for row in r["rows"]:
    if row["bucket"] == "UNDECODABLE":
        if not row.get("reason"):
            sys.exit("FAIL: UNDECODABLE row at %#x has no reason" % row["addr"])
        if row.get("name") or row.get("tier"):
            sys.exit("FAIL: UNDECODABLE row at %#x also carries a label" % row["addr"])
print("OK: %d functions = AUTHOR %d + LIBRARY %d + UNKNOWN %d + UNDECODABLE %d "
      "(%d decodable)" % (n, c["AUTHOR"], c["LIBRARY"], c["UNKNOWN"],
                          c["UNDECODABLE"], r["n_decodable"]))
'
else
  echo "SKIP: unhusk binary or shipped DB not present"
fi

if [ -f "$SHIPPED_DB" ]; then
  echo "-- triage.py UNDECODABLE branch (no corpus binary hits it naturally) --"
  # Real binaries in this corpus decode 100% of their FDEs, so the bucket that
  # exists to catch hash_functions() skips is never exercised by the runs above.
  # Force it: drop two entries from the hash map and assert they are reported as
  # UNDECODABLE rather than absorbed into UNKNOWN. unhusk is stubbed out so the
  # check is hermetic and does not depend on author attribution.
  BIN="$CORPUS/dust.stripped" DB="$SHIPPED_DB" python3 -c '
import os, sys
import triage as T

real_hash = T.hash_functions
dropped = []

def holey(path, funcs):
    h = real_hash(path, funcs)
    for i in list(h)[:2]:
        dropped.append(i)
        del h[i]
    return h

T.hash_functions = holey
T.run_unhusk = lambda *a, **k: []

r = T.triage(os.environ["BIN"], T.load_db(os.environ["DB"]), "unused", [], 2, None, 0.08)
c, n = r["counts"], r["n_functions"]
if c["UNDECODABLE"] != len(dropped):
    sys.exit("FAIL: dropped %d hashes, UNDECODABLE=%d" % (len(dropped), c["UNDECODABLE"]))
if sum(c[b] for b in ("AUTHOR", "LIBRARY", "UNKNOWN", "UNDECODABLE")) != n:
    sys.exit("FAIL: buckets do not sum to n_functions with UNDECODABLE present")
if r["n_decodable"] != n - len(dropped):
    sys.exit("FAIL: n_decodable did not shrink by the dropped functions")
und = [row for row in r["rows"] if row["bucket"] == "UNDECODABLE"]
if {row["addr"] for row in und} != {r["rows"][i]["addr"] for i in dropped}:
    sys.exit("FAIL: UNDECODABLE rows are not the ones whose hash was dropped")
if not all(row.get("reason") for row in und):
    sys.exit("FAIL: UNDECODABLE row without a reason")
print("OK: %d forced skips reported as UNDECODABLE (%s), n_decodable %d of %d"
      % (len(und), und[0]["reason"], r["n_decodable"], n))
'
fi
