#!/usr/bin/env python3
"""round8 -- does a RELATIVE (fraction-of-donor-pool) confidence threshold
hold precision more stable as the donor pool grows than an absolute
min_donor_bins count?

Found while growing the corpus 32->66 crates: at a FIXED min_donor_bins,
precision drifted down as donors grew (e.g. trippy bins=3: 87.4% at 32
donors -> 78.1% at 66 donors) while recall roughly doubled. Plausible cause:
generic/boilerplate code (clap arg parsing, anyhow error paths, derived
Debug impls) that's structurally similar across many independently-written
CLI tools gets more chances to hit any FIXED absolute bin count as the pool
grows, without being any more trustworthy. A threshold expressed as a
fraction of the current pool size should scale with that automatically.
"""
from __future__ import annotations
import os
import collections, pickle, sys

sys.path.insert(0, os.environ.get('RUSTSIG_DIR', '../../rustsig'))
from evaluate import score, prepare_target, CROSS, SAMECRATE  # noqa: E402
from rustsig import is_forwarding_shim  # noqa: E402


def build_db_frac(per_crate, donors, min_frac):
    n_donors = len(donors)
    min_bins = max(1, round(min_frac * n_donors))
    h2 = collections.defaultdict(list)
    for c in donors:
        for x, n_insns, erased, rep in per_crate.get(c, []):
            h2[x].append((c, erased, rep))
    db = {}
    for x, obs in h2.items():
        keys = {e for _, e, _ in obs}
        if len(keys) != 1:
            continue
        erased = next(iter(keys))
        if is_forwarding_shim(erased):
            continue
        n_bins = len({c for c, _, _ in obs})
        if n_bins < min_bins:
            continue
        rep = sorted((r for _, _, r in obs), key=len)[0]
        db[x] = (erased, rep, n_bins)
    return db, min_bins


def main():
    all_targets = [(ts, c) for ts, targets in (('cross', CROSS), ('samecrate', SAMECRATE))
                   for c in targets]
    print("preparing targets (disassembly, cached across all fractions/pools)...",
          file=sys.stderr, flush=True)
    preps = {c: prepare_target(c) for _, c in all_targets}

    for cache_path, label in [('round8/results/donor_index.pkl', '32-donor'),
                               ('round8/results/donor_index_full.pkl', '110-donor')]:
        with open(cache_path, 'rb') as fh:
            per_crate = pickle.load(fh)
        donors_full = sorted(per_crate.keys())
        print(f'=== {label} pool ({len(donors_full)} crates) ===', flush=True)
        for frac in (0.03, 0.05, 0.08, 0.10, 0.15):
            precs, recs, min_bins_seen = [], [], []
            for _, crate in all_targets:
                donors = [c for c in donors_full if c != crate]
                db, min_bins = build_db_frac(per_crate, donors, frac)
                r = score(preps[crate], db)
                precs.append(r['naming_precision'])
                recs.append(r['library_recall'])
                min_bins_seen.append(min_bins)
            precs.sort()
            recs.sort()
            mid = len(precs) // 2
            print(f'  frac={frac:.2f} (bins~{min_bins_seen[0]}) '
                  f'median_prec={precs[mid]:.1f} min_prec={precs[0]:.1f} '
                  f'median_recall={recs[mid]:.1f}', flush=True)


if __name__ == '__main__':
    main()
