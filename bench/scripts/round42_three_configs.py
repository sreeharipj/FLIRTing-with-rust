import json,os,subprocess,sys,bisect
S=os.environ.get('SCRATCH', '/tmp/flirting-bench')
GT=os.environ.get('GT_DIR', '../results/gt')
OUT=os.environ.get('CORPUS_OUT', 'corpus/out')
crate=sys.argv[1]
sigdir=f"{S}/{crate}_sigs"
sigs=sorted(os.path.abspath(os.path.join(sigdir,f)) for f in os.listdir(sigdir) if f.endswith(".sig"))
rows=[]
for line in open(f"{GT}/{crate}.gt.tsv"):
    if line.startswith("GTDUMP\t"):
        _,s,e,l,*r=line.rstrip("\n").split("\t"); rows.append((int(s,16),int(e,16),l))
rows.sort(); st=[r[0] for r in rows]; en=[r[1] for r in rows]; lb=[r[2] for r in rows]
scoreable={st[i] for i in range(len(rows)) if lb[i] in ("USER","LIB")}
lib={st[i] for i in range(len(rows)) if lb[i]=="LIB"}
zfs=[f"zfs {s}" for s in sigs]
configs={"aaa":["aaa"]+zfs+["aflj"],
         "aaa;aap":["aaa","aap"]+zfs+["aflj"],
         "fde-seeded":[f"af @ 0x{a:x}" for a in sorted(set(st))]+zfs+["aflj"]}
res={}
for tag,cmds in configs.items():
    sc=f"{S}/{crate}.{tag.replace(';','_')}.r2"
    open(sc,"w").write("\n".join(cmds)+"\n")
    p=subprocess.run(["r2","-q","-e","scr.color=0","-i",sc,f"{OUT}/{crate}.stripped"],capture_output=True,text=True,timeout=10800)
    fns=None
    for line in reversed(p.stdout.splitlines()):
        line=line.strip()
        if line.startswith("[") and line.endswith("]"):
            try: fns=json.loads(line); break
            except: continue
    hit=set(); cov=set()
    for fn in fns:
        a=fn["addr"]; i=bisect.bisect_right(st,a)-1
        if i<0 or a>=en[i]: continue
        o=st[i]
        if o in scoreable:
            cov.add(o)
            if fn.get("name","").startswith("flirt."): hit.add(o)
    size={st[i]:en[i]-st[i] for i in range(len(rows))}
    totb=sum(size[x] for x in lib)
    res[tag]={"r2fns":len(fns),"ceiling":100*len(cov&lib)/len(lib),"recall":100*len(hit&lib)/len(lib),
              "matched":len(hit&lib),"recall_bytes":100*sum(size[x] for x in hit&lib)/totb,
              "hits":sorted(hit&lib)}
res["n_lib"]=len(lib); res["n_sigs"]=len(sigs); res["crate"]=crate
json.dump(res,open(f"{S}/{crate}.threeconfig.json","w"),indent=1)
print(f"{crate}: sigs={len(sigs)} n_lib={len(lib)} | " + " | ".join(f"{t}: ceil {res[t]['ceiling']:.1f}% recall {res[t]['recall']:.2f}% (bytes {res[t]['recall_bytes']:.2f}%)" for t in ("aaa","aaa;aap","fde-seeded")))
