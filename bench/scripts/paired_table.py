"""Combine paired RIFT runs (on unhusk's binaries, scored by RIFT's own scorer)
with rustsig's numbers on the identical binaries and ruler."""
import glob, json, os, re, statistics as st
MINE={r['crate']:r for r in (json.loads(l) for l in open(
        os.environ.get('RESULTS_DIR', '../results') + '/bench.log') if l.startswith('{'))
      if r['config']=='std-only'}
SIB={r['crate']:r for r in (json.loads(l) for l in open(
        os.environ.get('RESULTS_DIR', '../results') + '/bench.log') if l.startswith('{'))
     if r['config']=='sibling'}
def uses_lto(crate):
    for p in glob.glob(os.path.expanduser(f"~/.cargo/registry/src/*/{crate}-*/Cargo.toml")):
        m=re.search(r"\[profile\.release\](.*?)(\n\[|\Z)",open(p,errors="ignore").read(),re.S)
        if m:
            x=re.search(r"^\s*lto\s*=\s*(.+)$",m.group(1),re.M)
            if x: return x.group(1).strip().strip('"') not in ('false','off')
    return False
rows=[]
for mp in sorted(glob.glob('/tmp/riftrun/*/metrics.json')):
    m=json.load(open(mp)); c=m['name']
    if c not in MINE: continue
    if m['n_truth_library']!=MINE[c]['n_truth_library']:
        print(f"  !! denominator mismatch {c}: rift {m['n_truth_library']} vs mine {MINE[c]['n_truth_library']}")
        continue
    rows.append(dict(crate=c, lto=uses_lto(c), n_lib=m['n_truth_library'],
                     rift=m['rift']['library_recall'], sigs=m.get('n_sigs'),
                     std=MINE[c]['library_recall'], sib=SIB[c]['library_recall'],
                     prec=MINE[c]['naming_precision']))
rows.sort(key=lambda r:r['crate'])
print(f"\nPAIRED: same binary, same ruler, RIFT scored by its own score_headtohead.py")
print(f"{'crate':<11}{'LTO':>5}{'n_lib':>7}{'RIFT':>8}{'rustsig-std':>13}{'x':>6}{'rustsig-sib':>13}{'namePrec':>10}")
for r in rows:
    print(f"{r['crate']:<11}{('Y' if r['lto'] else 'n'):>5}{r['n_lib']:>7}{r['rift']:>7.1f}%"
          f"{r['std']:>12.1f}%{r['std']/r['rift'] if r['rift'] else 0:>6.1f}{r['sib']:>12.1f}%{r['prec']:>9.1f}%")
if rows:
    print(f"\nn={len(rows)}  median RIFT {st.median(r['rift'] for r in rows):.1f}%"
          f"   median rustsig-std {st.median(r['std'] for r in rows):.1f}%"
          f"   median ratio {st.median(r['std']/r['rift'] for r in rows if r['rift']):.1f}x")
    for lto in (True,False):
        v=[r for r in rows if r['lto']==lto]
        if v: print(f"  {'LTO   ' if lto else 'no-LTO'} n={len(v)}: RIFT {st.median(r['rift'] for r in v):5.1f}%"
                    f"   rustsig-std {st.median(r['std'] for r in v):5.1f}%"
                    f"   ratio {st.median(r['std']/r['rift'] for r in v if r['rift']):.1f}x")
    json.dump(rows,open(os.environ.get('RESULTS_DIR', '../results') + '/paired.json','w'),indent=1)
