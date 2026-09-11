#!/usr/bin/env python3
"""round8 -- index the donor corpus once, cache it, so every downstream
experiment (threshold sweeps, confidence signals, call-graph refinement)
reuses the same expensive disassembly pass instead of repeating it.

Donor corpus: unhusk's realval/corpus_src -- 32 crates with .debug twins,
up from round40's 13 (bat/dust/fd/grex/hexyl/hyperfine/just/pastel/ripgrep/
sd/tokei/xsv/zoxide). starship and trippy are IN this 32 -- keep that in
mind in evaluate.py: they make a same-crate-different-build donor case,
distinct from ast-grep/wiki-tui/zellij which have zero crate overlap with
any donor (true cross-corpus).

For each donor binary we keep, per function: the body hash, n_insns, and
demangled+generic-erased name. Raw (not yet deduplicated/filtered) so
evaluate.py can build different DB configurations from the same cache.
"""
from __future__ import annotations
import collections, pickle, os, sys, time
from concurrent.futures import ProcessPoolExecutor, as_completed

sys.path.insert(0, os.environ.get(
    'RUSTSIG_DIR',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'rustsig')))
# read_fdes / hash_functions were split into cgumap / bodyhash modules in the
# author's dev tree that never shipped; both are part of rustsig.py itself.
from rustsig import (read_fdes, hash_functions, symbols,    # noqa: E402
                     demangle, erase_generics)

CORPUS_SRC = os.environ.get('CORPUS_OUT', 'corpus/corpus_src')
CORPUS_GROW = os.environ.get('CORPUS_OUT', 'corpus/out')
CACHE = os.environ.get('RESULTS_DIR', '../results') + '/donor_index.pkl'
CACHE_FULL = os.environ.get('RESULTS_DIR', '../results') + '/donor_index_full.pkl'

# held-out cross-corpus test targets -- must NEVER enter the donor pool, even
# if a same-named crate shows up in a source directory scanned here.
HELD_OUT = {'zellij', 'ast-grep', 'wiki-tui'}


def crates_in(src_dir):
    if not os.path.isdir(src_dir):
        return []
    return sorted(f[:-len('.debug')] for f in os.listdir(src_dir)
                  if f.endswith('.debug') and f[:-len('.debug')] not in HELD_OUT)


CRATES = crates_in(CORPUS_SRC)


def is_rust_mangled(name):
    """Donor binaries statically link C/asm libraries (aws-lc, oniguruma,
    sqlite3, openssl `lh_*` thunks, ...) whose local symbols also survive in
    `nm` output. Those are overwhelmingly short, generic, byte-identical
    trampolines across totally unrelated functions (e.g. every openssl
    `lh_TYPE_doall_arg_thunk` is a 2-insn jmp) -- pure collision fuel with no
    Rust identity to offer. rustsig's job is Rust bodies; keep the DB to
    symbols that are actually Rust-mangled (legacy `_ZN` or v0 `_R`)."""
    return name.startswith('_ZN') or name.startswith('_R')


def index_one(crate, src_dir=CORPUS_SRC):
    t0 = time.time()
    path = os.path.join(src_dir, crate + '.debug')
    fs = read_fdes(path)
    if not fs:
        return crate, []
    h = hash_functions(path, fs)
    nm = symbols(path)
    raw = []
    names_needed = set()
    for j, (x, n_insns) in h.items():
        name = nm.get(fs[j].start)
        if name and is_rust_mangled(name):
            raw.append((x, n_insns, name))
            names_needed.add(name)
    dem = demangle(sorted(names_needed))
    rows = [(x, n_insns, erase_generics(dem.get(n, n)), dem.get(n, n))
             for x, n_insns, n in raw]
    print(f"  {crate}: {len(fs)} fdes, {len(rows)} named "
          f"({time.time()-t0:.1f}s)", file=sys.stderr, flush=True)
    return crate, rows


def main():
    full = '--full' in sys.argv
    if full:
        # combine the original 32-crate pool with whatever grow_corpus.sh has
        # produced so far -- safe to run mid-growth, just indexes less.
        jobs = ([(c, CORPUS_SRC) for c in crates_in(CORPUS_SRC)] +
                [(c, CORPUS_GROW) for c in crates_in(CORPUS_GROW)
                 if c not in crates_in(CORPUS_SRC)])
        cache_path = CACHE_FULL
    else:
        jobs = [(c, CORPUS_SRC) for c in CRATES]
        cache_path = CACHE

    print(f"indexing {len(jobs)} donor crates"
          f"{' (corpus_src + corpus_grow)' if full else f' from {CORPUS_SRC}'}",
          file=sys.stderr)
    per_crate = {}
    with ProcessPoolExecutor(max_workers=min(16, len(jobs))) as ex:
        futs = {ex.submit(index_one, c, d): c for c, d in jobs}
        for fut in as_completed(futs):
            crate, rows = fut.result()
            if rows:
                per_crate[crate] = rows
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, 'wb') as fh:
        pickle.dump(per_crate, fh)
    total = sum(len(v) for v in per_crate.values())
    print(f"wrote {cache_path}: {len(per_crate)} crates, {total} named functions",
          file=sys.stderr)


if __name__ == '__main__':
    main()
