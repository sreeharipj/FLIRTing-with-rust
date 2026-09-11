#!/usr/bin/env python3
"""Extract, from one unstripped binary: every concrete subprogram body and every
DW_TAG_inlined_subroutine instance, each with normalised token hashes under three
alphabets. One JSONL row per item. Shares rustsig's tokeniser rules exactly for A0.

Alphabets:
  A0 = rustsig's own rule (mnemonic + register ids + masked imm/mem)   -- exact
  A1 = mnemonic + operand *kinds* (register identity dropped, imm value kept when unmasked)
  A2 = mnemonic only

Inline-instance ranges come from DW_AT_low_pc/high_pc only; instances expressed with
DW_AT_ranges are skipped, so every count here is a LOWER BOUND.
"""
import re, sys, json, gzip, subprocess, hashlib, os
sys.path.insert(0, os.environ.get('RUSTSIG_DIR', '../../rustsig'))
import rustsig
from capstone import *
from capstone.x86 import *

TAG = re.compile(r'^0x[0-9a-f]+:(\s*)DW_TAG_(\w+)')
ATT = re.compile(r'^\s+DW_AT_(\w+)\s*\((.*)\)\s*$')
QUO = re.compile(r'"([^"]*)"')


def parse_dwarf(path):
    """-> (subprograms, inlines); each item dict(lo,hi,nm,depth)."""
    p = subprocess.Popen(['llvm-dwarfdump', '--debug-info', path],
                         stdout=subprocess.PIPE, text=True, errors='replace', bufsize=1 << 20)
    subs, inls = [], []
    cur = None

    def flush(c):
        if not c or 'lo' not in c or 'nm' not in c:
            return
        hi = c.get('hi', 0)
        # llvm prints high_pc as a length OR as an address. The ambiguous case is a
        # parsed value EQUAL to low_pc: the length branch then yields hi = 2*lo, a
        # range of megabytes starting at the instance. 999 of 1,695,107 instances in
        # the 13-donor corpus hit this and every one had bytes == lo exactly
        # (ROUND48_C2_BYTE_CENSUS.md sec.3). Zero-length under either reading -> drop.
        if hi == c['lo']:
            return
        hi = hi if hi > c['lo'] else c['lo'] + hi
        if hi <= c['lo']:
            return
        rec = {'lo': c['lo'], 'hi': hi, 'nm': c['nm'], 'depth': c['depth']}
        (subs if c['tag'] == 'subprogram' else inls).append(rec)

    for line in p.stdout:
        m = TAG.match(line)
        if m:
            flush(cur)
            t = m.group(2)
            cur = {'tag': t, 'depth': len(m.group(1)) // 2} if t in ('subprogram', 'inlined_subroutine') else None
            continue
        if cur is None:
            continue
        a = ATT.match(line)
        if not a:
            continue
        k, v = a.group(1), a.group(2)
        if k == 'low_pc':
            try: cur['lo'] = int(v.split()[0], 16)
            except ValueError: pass
        elif k == 'high_pc':
            try: cur['hi'] = int(v.split()[0], 16)
            except ValueError: pass
        elif k in ('abstract_origin', 'specification', 'linkage_name'):
            q = QUO.search(v)
            if q: cur['nm'] = q.group(1)
        elif k == 'name' and 'nm' not in cur:
            q = QUO.search(v)
            if q: cur['nm'] = q.group(1)
    flush(cur)
    p.stdout.close(); p.wait()
    return subs, inls


def tokenise(md, blob, start, lo_mask, hi_mask):
    """-> list of (addr, a0, a1, a2). Mirrors rustsig.hash_functions for a0."""
    out = []
    for ins in md.disasm(blob, start):
        t0 = [ins.mnemonic]; t1 = [ins.mnemonic]
        grp = ins.groups
        ctl = (X86_GRP_JUMP in grp) or (X86_GRP_CALL in grp)
        try: ops = ins.operands
        except Exception: ops = []
        for op in ops:
            if op.type == CS_OP_REG:
                t0.append('r%d' % op.reg); t1.append('R')
            elif op.type == CS_OP_IMM:
                v = op.imm
                if ctl or (lo_mask <= v < hi_mask):
                    t0.append('i@'); t1.append('i@')
                else:
                    t0.append('i%d' % v); t1.append('i%d' % v)
            elif op.type == CS_OP_MEM:
                m = op.mem
                if m.base == X86_REG_RIP:
                    t0.append('m[rip+@]'); t1.append('M@')
                else:
                    t0.append('m[%d,%d,%d,%d]' % (m.base, m.index, m.scale, m.disp)); t1.append('M')
        out.append((ins.address, ' '.join(t0), ' '.join(t1), ins.mnemonic))
    return out


def h(toks):
    return hashlib.blake2b('\n'.join(toks).encode(), digest_size=16).hexdigest()


def p4(toks):
    """prefix hash over the first 4 tokens -- a cheap index for the blind scan"""
    return hashlib.blake2b('\n'.join(toks[:4]).encode(), digest_size=8).hexdigest()


def main(path, outp):
    subs, inls = parse_dwarf(path)
    base, data = rustsig.text_bytes(path)
    lo_mask, hi_mask = base, base + len(data)
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True

    # dedupe concrete subprograms by start; disassemble each once, aligned from its own start
    subs = {s['lo']: s for s in sorted(subs, key=lambda s: (s['lo'], -s['hi']))}
    byaddr = []          # (lo, hi, tokens)
    rows = []
    for lo, s in sorted(subs.items()):
        o = lo - base
        if o < 0 or o >= len(data):
            continue
        blob = data[o:min(s['hi'] - base, len(data))]
        toks = tokenise(md, blob, lo, lo_mask, hi_mask)
        if not toks:
            continue
        byaddr.append((lo, s['hi'], toks))
        rows.append({'kind': 'fn', 'nm': s['nm'], 'lo': lo, 'n': len(toks),
                     'a0': h([t[1] for t in toks]), 'a1': h([t[2] for t in toks]),
                     'a2': h([t[3] for t in toks]), 'p4': p4([t[1] for t in toks])})
    byaddr.sort()
    starts = [b[0] for b in byaddr]
    import bisect
    n_skip = 0
    for it in inls:
        i = bisect.bisect_right(starts, it['lo']) - 1
        if i < 0 or byaddr[i][1] <= it['lo']:
            n_skip += 1
            continue
        # An inlined range cannot outlive its host: clip, so `bytes` stays consistent
        # with `n` (which is bounded by the host's tokens whatever high_pc said).
        hi = min(it['hi'], byaddr[i][1])
        if hi <= it['lo']:
            n_skip += 1
            continue
        toks = [t for t in byaddr[i][2] if it['lo'] <= t[0] < hi]
        if not toks:
            n_skip += 1
            continue
        rows.append({'kind': 'inl', 'nm': it['nm'], 'lo': it['lo'], 'n': len(toks),
                     'depth': it['depth'], 'host': byaddr[i][0],
                     'bytes': hi - it['lo'],
                     'a0': h([t[1] for t in toks]), 'a1': h([t[2] for t in toks]),
                     'a2': h([t[3] for t in toks]), 'p4': p4([t[1] for t in toks])})
    with gzip.open(outp, 'wt') as f:
        for r in rows:
            f.write(json.dumps(r) + '\n')
    sys.stderr.write('%s: %d fn, %d inl (%d unmappable)\n'
                     % (os.path.basename(path), len(byaddr), len(rows) - len(byaddr), n_skip))


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
