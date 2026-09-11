#!/usr/bin/env python3
"""round8 -- test whether a confidence signal recovers cross-corpus naming
precision (round40 found it collapses 98.9% -> 33-53%: bodies still match,
but often the WRONG function, because short/generic instruction skeletons
collide across independently-compiled binaries).

Two target sets, both from RIFT's own benchmark corpus (never in the donor
index):
  cross   -- ast-grep, wiki-tui, zellij: crate has ZERO overlap with any of
             the 32 donor crates. This is round40's precision-collapse case.
  samecrate -- starship, trippy: the crate itself IS in the donor set (a
             different, unhusk-built binary of the same source), so this
             tests "have I seen this crate before, different build" as an
             intermediate case between true-unseen and identical-build.

Confidence signals tested, independently and combined:
  min_insns      -- drop DB entries / matches with fewer than N instructions
                     (short-function birthday-paradox hypothesis)
  min_donor_bins -- drop DB entries confirmed by fewer than N distinct
                     source binaries (breadth-of-confirmation hypothesis)
"""
from __future__ import annotations
import collections, itertools, json, os, pickle, sys

sys.path.insert(0, os.environ.get(
    'RUSTSIG_DIR',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'rustsig')))
# read_fdes / hash_functions were split into cgumap / bodyhash modules in the
# author's dev tree that never shipped; both are part of rustsig.py itself.
from rustsig import (read_fdes, hash_functions, symbols,    # noqa: E402
                     demangle, erase_generics, is_forwarding_shim)

CACHE = os.environ.get('RESULTS_DIR', '../results') + '/donor_index.pkl'
RIFT_BIN = os.environ.get('RIFT_BENCH_BIN', '')
RIFT_GT = os.environ.get('RIFT_BENCH_GT', '')
OUT_PATH = os.environ.get('RESULTS_DIR', '../results') + '/sweep.jsonl'

CROSS = ['ast-grep', 'wiki-tui', 'zellij']
SAMECRATE = ['starship', 'trippy']


def load_gt(crate):
    out = {}
    p = os.path.join(RIFT_GT, crate + '.gt.tsv')
    for line in open(p):
        f = line.rstrip('\n').split('\t')
        if len(f) >= 4 and f[0] == 'GTDUMP':
            try:
                out[int(f[1], 16)] = f[3]
            except ValueError:
                pass
    return out


def build_db(per_crate, donor_crates, min_insns=0, min_donor_bins=0):
    """-> {hash: (erased_name, rep_name, n_insns, n_bins)}, ambiguous hashes
    (different erased names across occurrences) always dropped -- that part
    of round36's design was already sound and is not what round40 broke."""
    h2 = collections.defaultdict(list)  # hash -> [(crate, n_insns, erased, rep)]
    for c in donor_crates:
        for x, n_insns, erased, rep in per_crate.get(c, []):
            h2[x].append((c, n_insns, erased, rep))
    db = {}
    for x, obs in h2.items():
        keys = {erased for _, _, erased, _ in obs}
        if len(keys) != 1:
            continue
        erased = next(iter(keys))
        if is_forwarding_shim(erased):
            continue
        n_bins = len({c for c, _, _, _ in obs})
        n_insns = obs[0][1]
        if n_insns < min_insns or n_bins < min_donor_bins:
            continue
        rep = sorted((r for _, _, _, r in obs), key=len)[0]
        db[x] = (erased, rep, n_insns, n_bins)
    return db


def prepare_target(crate):
    """Expensive part (disassembly) done once per crate, reused across the
    whole threshold sweep."""
    stripped = os.path.join(RIFT_BIN, crate + '.stripped')
    debug = os.path.join(RIFT_BIN, crate + '.debug')
    gt = load_gt(crate)
    fs = read_fdes(stripped)
    h = hash_functions(stripped, fs)
    nm = symbols(debug)
    names = [nm.get(f.start) for f in fs]
    dem = demangle(sorted({n for n in names if n}))
    truth_name = {i: erase_generics(dem.get(n, n)) for i, n in enumerate(names) if n}
    n_lib = sum(1 for v in gt.values() if v == 'LIB')
    return dict(crate=crate, fs=fs, h=h, gt=gt, truth_name=truth_name, n_lib=n_lib)


def score(prep, db):
    fs, h, gt, truth_name, n_lib = (prep['fs'], prep['h'], prep['gt'],
                                     prep['truth_name'], prep['n_lib'])
    matched = named = correct = 0
    for j, (x, n_insns) in h.items():
        k = db.get(x)
        if k is None:
            continue
        named += 1
        if gt.get(fs[j].start) == 'LIB':
            matched += 1
        if j in truth_name and truth_name[j] == k[0]:
            correct += 1
    return dict(crate=prep['crate'], n_funcs=len(fs), n_truth_library=n_lib,
                named=named, library_matched=matched,
                library_recall=100.0 * matched / n_lib if n_lib else 0.0,
                naming_precision=100.0 * correct / named if named else 0.0)


def main():
    cache_path = CACHE
    out_path = OUT_PATH
    if '--full' in sys.argv:
        cache_path = os.environ.get('RESULTS_DIR', '../results') + '/donor_index_full.pkl'
        out_path = os.environ.get('RESULTS_DIR', '../results') + '/sweep_full.jsonl'
    with open(cache_path, 'rb') as fh:
        per_crate = pickle.load(fh)
    donors_full = sorted(per_crate.keys())
    print(f"donor pool: {len(donors_full)} crates ({', '.join(donors_full)})\n",
          file=sys.stderr)

    sweeps = []
    for min_insns in (0, 3, 5, 8, 12, 16, 24, 32, 48, 64):
        for min_bins in (1, 2, 3, 5):
            sweeps.append((min_insns, min_bins))

    rows = []
    for target_set_name, targets in (('cross', CROSS), ('samecrate', SAMECRATE)):
        for crate in targets:
            print(f"preparing target {crate}...", file=sys.stderr)
            prep = prepare_target(crate)
            donors = [c for c in donors_full if c != crate]
            for min_insns, min_bins in sweeps:
                db = build_db(per_crate, donors, min_insns, min_bins)
                r = score(prep, db)
                r.update(target_set=target_set_name, min_insns=min_insns,
                          min_donor_bins=min_bins, db_hashes=len(db))
                rows.append(r)
                print(json.dumps(r), flush=True)

    with open(out_path, 'w') as fh:
        for r in rows:
            fh.write(json.dumps(r) + '\n')
    print(f"\nwrote {out_path}: {len(rows)} rows", file=sys.stderr)


if __name__ == '__main__':
    main()
