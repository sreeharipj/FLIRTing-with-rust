#!/usr/bin/env python3
"""THE GATE. Every fragment number so far assumed oracle boundaries -- the target's
own DWARF told us where each inlined range starts and ends. A stripped target does
not know that. This scans EVERY (start,length) window of every function in a
held-out, DWARF-blind target and measures what survives.

correct   = window is exactly a DWARF inlined instance whose erased identity == prediction
mislabel  = window is exactly a DWARF inlined instance with a DIFFERENT identity
unconfirmed = window is not a DWARF instance boundary at all (could be a real
              unrecorded inline, could be a false positive -- counted against us)"""
import sys, os, json, gzip, glob, collections, hashlib
sys.path.insert(0, os.environ.get('RUSTSIG_DIR', '../../rustsig'))
sys.path.insert(0, os.path.dirname(__file__))
import rustsig
from extract_inline import tokenise
from capstone import *
DATA = os.environ.get('INLINE_DATA', 'data')
OUT = os.environ.get('CORPUS_OUT', 'corpus/out')
MINLEN = int(sys.argv[1]) if len(sys.argv) > 1 else 8
HELD = sys.argv[2:] or ['pastel', 'hexyl', 'zoxide']
rows = {}
for p in sorted(glob.glob(DATA + '/*.jsonl.gz')):
    rows[os.path.basename(p).split('.')[0]] = [json.loads(l) for l in gzip.open(p, 'rt')]
names = sorted({r['nm'] for v in rows.values() for r in v})
mang = [n for n in names if rustsig.is_rust_mangled(n)]
dem = {}
for i in range(0, len(mang), 20000): dem.update(rustsig.demangle(mang[i:i+20000]))
ident = {n: rustsig.erase_generics(dem[n]) for n in mang}
def collapse(v):
    best = {}
    for r in v:
        if r['kind'] != 'inl' or r['nm'] not in ident: continue
        k = (r.get('host'), r['lo'], r['n'])
        c = best.get(k)
        if c is None or r.get('depth', 99) < c.get('depth', 99): best[k] = r
    return list(best.values())
col = {b: collapse(v) for b, v in rows.items()}
for held in HELD:
    m = collections.defaultdict(lambda: collections.defaultdict(set))
    for b, v in col.items():
        if b == held: continue
        for r in v:
            if r['n'] >= MINLEN: m[r['a0']][ident[r['nm']]].add(b)
    db = {h: next(iter(d)) for h, d in m.items()
          if len(d) == 1 and len(next(iter(d.values()))) >= 2}
    # prefix index: (hash of first 4 tokens) -> set of signature lengths
    pidx = collections.defaultdict(set)
    for b, v in col.items():
        if b == held: continue
        for r in v:
            if r['n'] >= MINLEN and r['a0'] in db: pidx[r['p4']].add(r['n'])
    L_ALL = sorted({L for s_ in pidx.values() for L in s_})
    truth = {}                                    # (lo, n) -> identity
    for r in col[held]:
        truth[(r['lo'], r['n'])] = ident[r['nm']]
    path = '%s/%s.debug' % (OUT, held)
    base, data = rustsig.text_bytes(path)
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    correct = mislabel = unconf = 0
    hit_ids = set(); scanned = 0
    for f in rustsig.read_fdes(path):
        o = f.start - base
        if o < 0 or o >= len(data): continue
        t = tokenise(md, data[o:min(f.end - base, len(data))], f.start, base, base + len(data))
        if len(t) < MINLEN: continue
        toks = [x[1] for x in t]; addrs = [x[0] for x in t]
        n = len(toks)
        for i in range(n):
            if i + MINLEN > n: break
            ph = hashlib.blake2b('\n'.join(toks[i:i+4]).encode(), digest_size=8).hexdigest()
            cand = pidx.get(ph)
            if not cand: continue
            for L in cand:
                if i + L > n: continue
                scanned += 1
                h = hashlib.blake2b('\n'.join(toks[i:i+L]).encode(), digest_size=16).hexdigest()
                g = db.get(h)
                if g is None: continue
                k = (addrs[i], L)
                if k in truth:
                    if truth[k] == g: correct += 1; hit_ids.add(g)
                    else: mislabel += 1
                else: unconf += 1
    tot = correct + mislabel + unconf
    print('%-9s minlen %2d | %d windows scanned, %d sig lengths | hits %d = correct %d (%.1f%%), '
          'mislabelled %d (%.1f%%), unconfirmed %d (%.1f%%) | %d identities named'
          % (held, MINLEN, scanned, len(L_ALL), tot, correct, 100.0*correct/max(1,tot),
             mislabel, 100.0*mislabel/max(1,tot), unconf, 100.0*unconf/max(1,tot), len(hit_ids)))
