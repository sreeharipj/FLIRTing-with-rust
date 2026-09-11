#!/usr/bin/env python3
"""Score rustsig on RIFT's benchmark axis: library_recall over the same ruler.

RIFT's harness records, per binary, `library_matched / n_truth_library`. This
computes the identical quantity for rustsig so the two are directly comparable,
plus rustsig's own naming precision (which RIFT gets for free from FLIRT).

Two database configurations, because they answer different questions:
  sibling  -- leave-one-out over the corpus (favourable: shares dependencies)
  std      -- std/core/alloc only (needs ZERO knowledge of the target, which is
              the configuration that removes RIFT's preconditions entirely)
"""
import collections, json, os, re, subprocess, sys

sys.path.insert(0, os.environ.get(
    'RUSTSIG_DIR',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'rustsig')))
# read_fdes / hash_functions were split into cgumap / bodyhash modules in the
# author's dev tree that never shipped; both are part of rustsig.py itself.
from rustsig import (read_fdes, hash_functions,             # noqa: E402
                     erase_generics, demangle, symbols)

OUT = os.environ.get('CORPUS_OUT', 'corpus/out')
GT = os.environ.get('GT_DIR', '../results/gt')
V0 = re.compile(r'C(?:s[0-9A-Za-z]+_)?(\d+)([A-Za-z_][A-Za-z0-9_]*)')
STD = {'core', 'alloc', 'std', 'hashbrown', 'compiler_builtins',
       'panic_unwind', 'unwind', 'addr2line', 'gimli', 'miniz_oxide',
       'object', 'adler2', 'rustc_demangle', 'memchr', 'cfg_if'}


def crate_of(n):
    if n.startswith('_R'):
        m = V0.search(n)
        return m.group(2)[:int(m.group(1))] if m else None
    m = re.match(r'^_ZN(\d+)([A-Za-z_][A-Za-z0-9_]*)', n)
    return m.group(2)[:int(m.group(1))] if m else None


def load_gt(crate):
    """-> {start_addr: 'LIB'|'USER'|'UNK'}"""
    out = {}
    p = os.path.join(GT, crate + '.gt.tsv')
    if not os.path.exists(p):
        return out
    for line in open(p):
        f = line.rstrip('\n').split('\t')
        if len(f) >= 4 and f[0] == 'GTDUMP':
            try:
                out[int(f[1], 16)] = f[3]
            except ValueError:
                pass
    return out


def index(path, std_only):
    """Build hash -> erased-path from an unstripped binary."""
    fs = read_fdes(path)
    if not fs:
        return {}
    h = hash_functions(path, fs)
    nm = symbols(path)
    h2 = collections.defaultdict(set)
    for j, (x, n) in h.items():
        name = nm.get(fs[j].start)
        if not name:
            continue
        if std_only and crate_of(name) not in STD:
            continue
        h2[x].add(name)
    return h2


def merge(dicts):
    out = collections.defaultdict(set)
    for d in dicts:
        for k, v in d.items():
            out[k] |= v
    return out


def finalize(h2):
    alln = sorted({n for v in h2.values() for n in v})
    dem = demangle(alln)
    db = {}
    for x, names in h2.items():
        keys = {erase_generics(dem.get(n, n)) for n in names}
        if len(keys) == 1:
            db[x] = next(iter(keys))
    return db


def score(crate, db):
    stripped = os.path.join(OUT, crate + '.stripped')
    debug = os.path.join(OUT, crate + '.debug')
    gt = load_gt(crate)
    if not gt:
        return None
    fs = read_fdes(stripped)
    h = hash_functions(stripped, fs)
    nm = symbols(debug)
    names = [nm.get(f.start) for f in fs]
    dem = demangle(sorted({n for n in names if n}))
    truth_name = {i: erase_generics(dem.get(n, n)) for i, n in enumerate(names) if n}
    n_lib = sum(1 for v in gt.values() if v == 'LIB')
    matched = named = correct = 0
    for j, (x, n) in h.items():
        k = db.get(x)
        if k is None:
            continue
        named += 1
        if gt.get(fs[j].start) == 'LIB':
            matched += 1
        if j in truth_name and truth_name[j] == k:
            correct += 1
    return dict(crate=crate, n_funcs=len(fs), n_truth_library=n_lib,
                named=named, library_matched=matched,
                library_recall=100.0 * matched / n_lib if n_lib else 0.0,
                naming_precision=100.0 * correct / named if named else 0.0)


if __name__ == '__main__':
    crates = sys.argv[1:] or ['bat', 'dust', 'fd', 'grex', 'hexyl', 'hyperfine',
                              'just', 'pastel', 'ripgrep', 'sd', 'tokei', 'xsv', 'zoxide']
    print("indexing corpus (this is the slow part)...", file=sys.stderr)
    full = {c: index(os.path.join(OUT, c + '.debug'), False) for c in crates}
    stdo = {c: index(os.path.join(OUT, c + '.debug'), True) for c in crates}
    rows = []
    for c in crates:
        db_sib = finalize(merge([full[o] for o in crates if o != c]))
        db_std = finalize(merge([stdo[o] for o in crates if o != c]))
        for tag, db in (('sibling', db_sib), ('std-only', db_std)):
            r = score(c, db)
            if r:
                r['config'] = tag
                r['db_hashes'] = len(db)
                rows.append(r)
                print(json.dumps(r), flush=True)
    with open(os.environ.get('RESULTS_DIR', '../results') + '/rustsig_bench.jsonl', 'w') as fh:
        for r in rows:
            fh.write(json.dumps(r) + '\n')
