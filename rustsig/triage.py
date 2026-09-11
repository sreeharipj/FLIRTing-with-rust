#!/usr/bin/env python3
"""triage -- combine rustsig (library naming) and unhusk (author-code
attribution) into one analyst-facing pass over a stripped Rust binary.

../docs/method.md §7 measured why this
composition is worth having -- the two tools sit at opposite operating
points (unhusk: high precision / low recall on author code; rustsig: lower
precision / high recall on library code) and together cut what an analyst
has to read by ~44% while keeping ~92% of the actual author code in view.
That was a measurement, not a tool: this is the tool. Every function in the
binary gets exactly one bucket:

  AUTHOR       -- unhusk attributed it to the binary's own source (by tier)
  LIBRARY      -- rustsig named it against the donor DB (not author-attributed)
  UNKNOWN      -- neither -- where an analyst's time is best spent
  UNDECODABLE  -- rustsig could not even form a body hash for it (start outside
                  .text, or capstone decoded zero instructions). Not evidence
                  of anything; broken out so it stops inflating UNKNOWN, and
                  excluded from the "read AUTHOR + UNKNOWN" denominator.

Usage:
  triage.py STRIPPED_BIN --rustsig-db DB.json.gz [--unhusk-bin PATH]
            [--crate NAME[,NAME...]] [--min-confidence-frac F] [--json]

Needs `unhusk` built (cargo build --release in ~/Videos/unhusk, or pass
--unhusk-bin). Everything else is the same as rustsig.py label.
"""
from __future__ import annotations
import argparse, bisect, json, os, subprocess, sys

from rustsig import read_fdes, hash_functions, load_db, text_bytes, is_rust_mangled  # noqa: E402

DEFAULT_UNHUSK = os.environ.get('UNHUSK_BIN', 'unhusk')


def run_unhusk(binary, unhusk_bin, crates, min_anchors):
    cmd = [unhusk_bin, binary, '--json', '--min-anchors', str(min_anchors)]
    for c in crates:
        cmd += ['--crate', c]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        # Author attribution is the optional half of the composition: without it
        # every function simply falls through to LIBRARY/UNKNOWN. Losing it is
        # much better than losing the run.
        print("warning: unhusk timed out after 300s; continuing with no author "
              "attribution (all functions will land in LIBRARY/UNKNOWN)", file=sys.stderr)
        return []
    if p.returncode != 0:
        print(f"warning: unhusk exited {p.returncode}: {p.stderr[:300]}", file=sys.stderr)
        return []
    try:
        return json.loads(p.stdout)['functions']
    except (json.JSONDecodeError, KeyError):
        print("warning: could not parse unhusk --json output", file=sys.stderr)
        return []


def triage(binary, db, unhusk_bin, crates, min_anchors, min_confidence, min_confidence_frac):
    fs = read_fdes(binary)
    if not fs:
        return None
    h = hash_functions(binary, fs)

    if min_confidence is None:
        n_donors = db.get('__meta__', {}).get('n_donors', 1)
        min_confidence = max(1, round(min_confidence_frac * n_donors))

    author_ranges = sorted(
        ((int(f['start'], 16), int(f['end'], 16), f['tier'], f['anchor_files'])
         for f in run_unhusk(binary, unhusk_bin, crates, min_anchors)),
        key=lambda r: r[0])

    # Ranges are sorted and non-overlapping, so the only candidate for `addr`
    # is the last range starting at or before it.
    author_starts = [r[0] for r in author_ranges]

    def author_hit(addr):
        i = bisect.bisect_right(author_starts, addr) - 1
        if i < 0:
            return None
        start, end, tier, files = author_ranges[i]
        return (tier, files) if addr < end else None

    # hash_functions() silently drops functions it cannot decode. Recover the
    # reason here so they are reported rather than absorbed into UNKNOWN.
    text_base, text_data = text_bytes(binary)
    text_end = text_base + len(text_data)

    rows = []
    for i, f in enumerate(fs):
        entry = h.get(i)
        lib = db.get(entry[0]) if entry else None
        lib_ok = lib and lib['confidence'] >= min_confidence
        au = author_hit(f.start)
        if au:
            bucket, detail = 'AUTHOR', dict(tier=au[0], files=au[1])
        elif lib_ok:
            bucket, detail = 'LIBRARY', dict(name=lib['rep'], confidence=lib['confidence'])
        elif entry is None:
            reason = ('outside .text' if not (text_base <= f.start < text_end)
                      else 'no instructions decoded')
            bucket, detail = 'UNDECODABLE', dict(reason=reason)
        else:
            bucket, detail = 'UNKNOWN', {}
        rows.append(dict(addr=f.start, size=f.size, bucket=bucket, **detail))

    counts = {'AUTHOR': 0, 'LIBRARY': 0, 'UNKNOWN': 0, 'UNDECODABLE': 0}
    for r in rows:
        counts[r['bucket']] += 1
    return dict(binary=binary, n_functions=len(fs), counts=counts,
                n_decodable=len(fs) - counts['UNDECODABLE'],
                min_confidence=min_confidence, rows=rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('binary')
    ap.add_argument('--rustsig-db', required=True)
    ap.add_argument('--unhusk-bin', default=DEFAULT_UNHUSK)
    ap.add_argument('--crate', default='', help='comma-separated root crate name(s), '
                     'passed to unhusk --crate (needed for cargo-install-style builds)')
    ap.add_argument('--min-anchors', type=int, default=2, help='unhusk --min-anchors')
    ap.add_argument('--min-confidence', type=int, default=None)
    ap.add_argument('--min-confidence-frac', type=float, default=0.08)
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--limit', type=int, default=0,
                     help='rows to print per bucket in table mode (0=all)')
    args = ap.parse_args()

    db = load_db(args.rustsig_db)
    crates = [c for c in args.crate.split(',') if c]
    result = triage(args.binary, db, args.unhusk_bin, crates,
                     args.min_anchors, args.min_confidence, args.min_confidence_frac)
    if result is None:
        print(f"{args.binary}: no functions found (no .eh_frame? not analyzable)",
              file=sys.stderr)
        sys.exit(1)

    if args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
        return

    n = result['n_functions']
    c = result['counts']
    n_dec = result['n_decodable']
    print(f"{args.binary}: {n} functions")
    for bucket in ('AUTHOR', 'LIBRARY', 'UNKNOWN', 'UNDECODABLE'):
        print(f"  {bucket:<11} {c[bucket]:>6}  ({100*c[bucket]/n:.1f}%)")
    to_read = c['AUTHOR'] + c['UNKNOWN']
    if n_dec:
        print(f"\n  read AUTHOR + UNKNOWN = {to_read} functions "
              f"({100*to_read/n_dec:.1f}% of the {n_dec} decodable functions) "
              f"instead of all {n_dec}")
    else:
        print(f"\n  no decodable functions ({n} skipped by hash_functions)")
    if c['UNDECODABLE']:
        print(f"  ({c['UNDECODABLE']} UNDECODABLE excluded from that denominator "
              f"-- rustsig never saw them, so they are not a triage result)")

    for bucket in ('AUTHOR', 'UNKNOWN', 'UNDECODABLE', 'LIBRARY'):
        rows = [r for r in result['rows'] if r['bucket'] == bucket]
        if not rows:
            continue
        print(f"\n{'addr':>12} {'size':>6}  {bucket}")
        shown = rows if not args.limit else rows[:args.limit]
        for r in shown:
            detail = (r.get('name') or r.get('reason')
                      or ','.join(r.get('files', []))[:60] or '')
            print(f"{r['addr']:>#12x} {r['size']:>6}  {detail}")
        if args.limit and len(rows) > args.limit:
            print(f"  ... and {len(rows) - args.limit} more (--limit 0 for all)")


if __name__ == '__main__':
    main()
