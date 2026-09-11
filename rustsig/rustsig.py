#!/usr/bin/env python3
"""rustsig -- name library functions in a STRIPPED Rust binary by body hash.

Complements RIFT (FLIRT byte-pattern signatures, Microsoft MIRAGE, REcon 2025)
and unhusk (author-code identification via panic Locations). Where FLIRT is
weakest -- monomorphized generic instantiations, whose byte patterns differ per
binary -- this is strongest: >99% of generic instantiations produce a
byte-identical normalised body hash across independently built binaries.

The trick is what you ask for. Asking "which exact symbol is this" collapses
precision, because `drop_glue<Vec<A>>` and `drop_glue<Vec<B>>` really do
compile to identical code. Asking "which *function* is this, ignoring the
type it was instantiated with" is both answerable and the question an
analyst actually wants.

Paired against RIFT on 13 real binaries, both tools given the same .eh_frame
function universe and scored by RIFT's own metric: median library recall
47.7% vs 24.7%, a rustsig win on 9 of 13 and a loss on 4 (grex, xsv, ripgrep,
tokei). The wins concentrate in the LTO stratum -- RIFT degrades 3.2x under
LTO because it recompiles from source and cannot reproduce the target's
link-time decisions, rustsig indexes linked binaries and degrades 1.08x.
RIFT remains better at exact symbol identity, at precision on C/asm code,
and needs no donor corpus at all. See ../docs/benchmark.md, including the
harness bug that made an earlier version of this comparison read 5.2x.

Cross-corpus naming precision was collapsing to 33-53% until nine causes were
found and fixed: donor breadth was undertested; the donor DB was absorbing
statically-linked C/asm library symbols with no Rust identity to offer;
`erase_generics` had two string-normalization bugs that scored correct
matches as collisions; an absolute confidence threshold needed re-tuning as
the donor pool grew; this donor corpus was built with an anomalously
bleeding-edge nightly (rustc changed which name it emits for the classic
destructor shim in the ~7 weeks before this was measured, so every donor
inherited the new one while virtually every real-world target still has the
old one); and a family of reference-forwarding shims
(`library/core/src/fmt/mod.rs`'s `fmt_refs!` macro and the identical idiom
in `alloc`'s Box/Rc/Arc) is structurally indistinguishable across every type
it is instantiated for once the call target is masked. Cross-corpus
precision now runs 98-99%, within a point of the within-corpus ceiling.
See ../docs/method.md. `--min-confidence-frac` (donor breadth, as a fraction
of pool size) is the most effective remaining lever for trading recall
against precision on an unfamiliar target -- read the threshold-sweep table
in README.md before picking a non-default value.

Usage:
  rustsig.py build DB.json BIN [BIN ...]        # BIN must have symbols (not stripped)
  rustsig.py label DB.json STRIPPED_BIN [--min-confidence N] [--json]

Needs on PATH: nm, objdump-compatible ELF (via pyelftools), rustfilt.
Python deps: capstone, pyelftools. PE targets additionally need `pefile`.

`label` also accepts a PE32+ target (donor DB still built from ELF donors --
the body hash is over raw instruction bytes, format-agnostic once a
(base_va, .text bytes) pair and a function-boundary list exist). PE's x64
.pdata RUNTIME_FUNCTION table is the COFF/PE analogue of ELF's .eh_frame FDEs
used below: an allocated section the OS loader needs for SEH unwinding, so
(like .eh_frame) it survives symbol stripping. `build`/donor-indexing stays
ELF+nm-only -- not needed to label a PE target against an existing DB.
"""
from __future__ import annotations
import argparse, collections, gzip, hashlib, json, re, signal, subprocess, sys
from dataclasses import dataclass

try:
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # `rustsig.py label ... | head` shouldn't traceback
except (AttributeError, ValueError):
    pass

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_REG, CS_OP_IMM, CS_OP_MEM
    from capstone.x86 import X86_REG_RIP, X86_GRP_JUMP, X86_GRP_CALL
    from elftools.elf.elffile import ELFFile
except ImportError as e:
    sys.exit(f"rustsig: missing dependency ({e}).\n"
              f"  pip install capstone pyelftools")


# ---------------------------------------------------------------- function boundaries

@dataclass
class Func:
    start: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start


def _is_pe(path: str) -> bool:
    with open(path, 'rb') as fh:
        return fh.read(2) == b'MZ'


def _read_fdes_pe(path: str) -> list[Func]:
    """Function [start,end) ranges from PE x64 .pdata (RUNTIME_FUNCTION
    table: BeginAddress/EndAddress/UnwindInfoAddress, 12 bytes each, RVAs).
    This is .eh_frame's PE/COFF counterpart -- required by the OS loader for
    SEH unwinding on x86-64, so (like .eh_frame) it's an allocated section
    that survives strip/symbol removal, not debug info. One caveat shared
    with .eh_frame: leaf functions that never touch the stack or call out
    are legally absent (no unwind info needed), so coverage is high but not
    literally 100% of .text -- confirmed empirically at 95.4% of .text on a
    real 2026-08 Rust/MSVC ransomware sample (MalwareBazaar)."""
    try:
        import pefile
    except ImportError:
        sys.exit("rustsig: PE target given but `pefile` is not installed.\n"
                  "  pip install pefile")
    import struct
    try:
        pe = pefile.PE(path, fast_load=True)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        pdata = next((s for s in pe.sections
                      if s.Name.rstrip(b'\x00') == b'.pdata'), None)
        if pdata is None:
            return []
        data = pdata.get_data(length=pdata.Misc_VirtualSize)
        out = []
        for i in range(len(data) // 12):
            begin, end, _unwind = struct.unpack_from('<III', data, i * 12)
            if end > begin:
                out.append(Func(start=image_base + begin, end=image_base + end))
    except Exception:
        return []
    out.sort(key=lambda f: f.start)
    dedup, seen = [], set()
    for f in out:
        if f.start in seen:
            continue
        seen.add(f.start)
        dedup.append(f)
    return dedup


def _text_bytes_pe(path: str):
    import pefile
    pe = pefile.PE(path, fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    s = next(s for s in pe.sections if s.Name.rstrip(b'\x00') == b'.text')
    return image_base + s.VirtualAddress, s.get_data()


def read_fdes(path: str) -> list[Func]:
    """Function [start,end) ranges from .eh_frame. Survives strip --strip-all,
    since .eh_frame is an allocated section required for unwinding -- this is
    rustsig's hard precondition: no .eh_frame, no functions to hash.

    Some real malware ships with a truncated or missing section header table
    (an anti-analysis technique, or just a partial/corrupted dump) -- found
    testing against a real MalwareBazaar Akira sample (../docs/limits.md §3). pyelftools
    raises ELFParseError deep inside section-header parsing for those, not a
    clean "no debug info" signal; treated the same as "not analyzable" here
    rather than propagating a traceback for something rustsig fundamentally
    can't do anything with anyway."""
    if _is_pe(path):
        return _read_fdes_pe(path)
    try:
        with open(path, 'rb') as fh:
            elf = ELFFile(fh)
            if not elf.has_dwarf_info():
                return []
            dw = elf.get_dwarf_info()
            entries = list(dw.EH_CFI_entries())
            out = []
            for e in entries:
                hdr = getattr(e, 'header', None)
                if hdr is None:
                    continue
                loc = getattr(hdr, 'initial_location', None)
                rng = getattr(hdr, 'address_range', None)
                if loc is None or rng is None or rng == 0:
                    continue
                out.append(Func(start=loc, end=loc + rng))
    except Exception:
        return []
    out.sort(key=lambda f: f.start)
    dedup, seen = [], set()
    for f in out:
        if f.start in seen:
            continue
        seen.add(f.start)
        dedup.append(f)
    return dedup


# ---------------------------------------------------------------- relocation-aware body hash

def text_bytes(path):
    if _is_pe(path):
        return _text_bytes_pe(path)
    with open(path, 'rb') as fh:
        elf = ELFFile(fh)
        s = elf.get_section_by_name('.text')
        return s['sh_addr'], s.data()


def hash_functions(path, funcs):
    """funcs: list of Func. -> {index: (hash, n_insns)}.

    Masks exactly what differs between two independently-linked copies of the
    same item and nothing else, using decoded operands rather than printed
    text: branch/call targets, RIP-relative displacements, and absolute
    immediates in the .text address range are relocation-dependent and get
    masked (.rodata addresses reach code as RIP-relative operands, which the
    displacement rule already masks -- the immediate bound below is .text
    only). Registers, stack displacements, small immediates, and
    operand sizes are kept -- those are what distinguish genuinely different
    functions that happen to look alike."""
    base, data = text_bytes(path)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    lo_mask, hi_mask = base, base + len(data)
    out = {}
    for i, f in enumerate(funcs):
        o = f.start - base
        if o < 0 or o >= len(data):
            continue
        blob = data[o:min(f.end - base, len(data))]
        toks = []
        n = 0
        for ins in md.disasm(blob, f.start):
            n += 1
            t = [ins.mnemonic]
            grp = ins.groups
            ctl = (X86_GRP_JUMP in grp) or (X86_GRP_CALL in grp)
            try:
                ops = ins.operands
            except Exception:
                ops = []
            for op in ops:
                if op.type == CS_OP_REG:
                    t.append('r%d' % op.reg)
                elif op.type == CS_OP_IMM:
                    v = op.imm
                    if ctl or (lo_mask <= v < hi_mask):
                        t.append('i@')
                    else:
                        t.append('i%d' % v)
                elif op.type == CS_OP_MEM:
                    m = op.mem
                    if m.base == X86_REG_RIP:
                        t.append('m[rip+@]')
                    else:
                        t.append('m[%d,%d,%d,%d]' % (m.base, m.index, m.scale, m.disp))
            toks.append(' '.join(t))
        if n:
            out[i] = (hashlib.blake2b('\n'.join(toks).encode(),
                                       digest_size=16).hexdigest(), n)
    return out


# ---------------------------------------------------------------- symbols / naming

def is_rust_mangled(name):
    """Statically-linked C/asm libraries (aws-lc, oniguruma, sqlite, openssl's
    `lh_*` thunks, ...) leave local symbols in `nm` output too. Those are
    overwhelmingly short, generic, byte-identical trampolines -- collision
    fuel with no Rust identity to offer, and matching against them is FLIRT's
    job, not rustsig's (../docs/method.md §5)."""
    return name.startswith('_ZN') or name.startswith('_R')


# ../docs/method.md §5: Box/Rc/Arc (and their Weak variants) forward several
# comparison/hashing traits to their inner value with the identical
# one-line-deref-and-call idiom `fmt_refs!` uses for `&T` -- confirmed by
# reading library/alloc/src/{boxed,rc,sync}.rs directly, not guessed. Only
# the methods actually confirmed trivial single-call forwards are listed;
# `clone` was checked and is NOT included -- Box::clone pre-allocates and
# calls `clone_to_uninit`, genuinely more than a masked-identical forward.
_FORWARDING_WRAPPERS = ('alloc::boxed::Box', 'alloc::rc::Rc', 'alloc::rc::Weak',
                         'alloc::sync::Arc', 'alloc::sync::Weak')
_FORWARDING_METHODS = ('fmt', 'eq', 'ne', 'partial_cmp', 'lt', 'le', 'ge', 'gt',
                        'cmp', 'hash')
_FORWARDING_EXACT = {f'{w}::{m}' for w in _FORWARDING_WRAPPERS for m in _FORWARDING_METHODS}


def is_forwarding_shim(erased_identity):
    """../docs/method.md §5: `library/core/src/fmt/mod.rs`'s `fmt_refs!` macro
    generates a one-line deref-and-forward impl of Debug/Display/Octal/
    Binary/LowerHex/UpperHex/LowerExp/UpperExp for `&T` and `&mut T`
    (`fn fmt(&self, f) { Trait::fmt(&**self, f) }`), and `alloc`'s
    Box/Rc/Arc (and their Weak variants) use the identical idiom for
    Debug/Display and several comparison/hashing traits. After masking the
    one thing that would distinguish them (the relocated call target),
    EVERY instantiation of one of these shims, for every concrete T
    anywhere in the ecosystem, hashes identically -- confirmed against the
    actual rustc/std source, not inferred. A donor's `T` is never the
    target's `T`: measured on RIFT's 5 cross-corpus targets, excluding the
    `&`/`&mut` half (Finding 7) raised median precision 93.3%->95.6% and
    the floor 85.8%->91.1%, for a recall cost of 0.3-2.4pp per target;
    adding the Box/Rc/Arc half (Finding 8) moved it a further 95.6%->95.7%
    -- small on this target set, but never negative, so kept."""
    return erased_identity.startswith('&') or erased_identity in _FORWARDING_EXACT


def symbols(path):
    out = subprocess.run(['nm', path], capture_output=True, text=True).stdout
    nm = {}
    for l in out.splitlines():
        q = l.split()
        if len(q) == 3 and q[1] in 'tT':
            nm.setdefault(int(q[0], 16), q[2])
    return nm


def demangle(names):
    if not names:
        return {}
    try:
        p = subprocess.run(['rustfilt'], input='\n'.join(names),
                            capture_output=True, text=True, timeout=300)
        out = p.stdout.splitlines()
        if p.returncode == 0 and len(out) == len(names):
            return dict(zip(names, out))
    except Exception:
        pass
    return {n: n for n in names}


def _impl_wrapper_type(inner):
    """`impl anyhow::Error` -> `anyhow::Error`; `impl core::fmt::Debug for
    anyhow::error::ContextError<C,E>` -> `anyhow::error::ContextError<C,E>`;
    `Vec<u8> as IntoIterator` -> `Vec<u8>`. The concrete Self type, not the
    trait, since that's the stable cross-toolchain identity."""
    if inner.startswith('impl '):
        inner = inner[len('impl '):]
    if ' for ' in inner:
        return inner.split(' for ', 1)[1]
    if ' as ' in inner:
        return inner.split(' as ', 1)[0]
    return inner


def erase_generics(s):
    """`Vec<u8>::push::h1234` -> `Vec::push` -- identity without the
    instantiation. ../docs/method.md: symbol-table names carry the legacy `::hHASH`
    suffix *after* an erased generic-parameter block, while DWARF DW_AT_name
    strings (ground truth on a stripped target's debug twin) never had a
    hash suffix to begin with -- one `::` before the generics, not two.

    ../docs/method.md §3: also unwraps `<SelfType [as Trait]>::method` / `<impl Trait
    for SelfType>::method` self-type wrappers to `SelfType::method` instead
    of discarding the type name wholesale -- and NOT just when the wrapper
    leads the whole string. Legacy mangling encodes an impl block's path
    using where it was lexically WRITTEN, so a trait impl written in one
    module for a type defined in another demangles as e.g.
    `anyhow::context::<impl core::fmt::Debug for
    anyhow::error::ContextError<C,E>>::fmt` -- a real symbol seen scoring as
    a false collision against v0-mangling's/rustc-demangle's canonical
    `anyhow::error::ContextError::fmt` for the exact same function, on the
    exact same toolchain-drift axis as the drop_glue/drop_in_place synonym
    below (this corpus's donors are overwhelmingly v0-mangled; real-world
    targets like the RIFT benchmark's zellij are legacy-mangled). Fix:
    whenever a standalone `<...>` path *component* (preceded by `::` or at
    the very start -- not a generic-parameter suffix glued to an
    identifier, which is handled by the erasure pass below) wraps an impl,
    replace the module-path-so-far with nothing and keep only the
    extracted Self type, since that -- not the impl's lexical location --
    is the function's real identity.

    A `::<` immediately before the bracket is ambiguous with this same
    check -- that's *also* "preceded by `:`", but it's turbofish
    (`drop_in_place::<Foo>`, `get_or_init::<T,F>`), not an impl wrapper,
    and must be left for the plain erasure pass below instead of eating
    everything before it. Real impl-wrapper brackets always start with the
    literal `impl ` keyword once past the very start of the string (a
    leading bracket, i==0, is unambiguous either way -- nothing precedes
    it to have a turbofish on), so that's the disambiguator."""
    i = 0
    while i < len(s):
        if s[i] == '<' and (i == 0 or s[i - 1] == ':'):
            depth, j = 1, i + 1
            while j < len(s) and depth > 0:
                if s[j] == '<':
                    depth += 1
                elif s[j] == '>' and s[j - 1] != '-':
                    depth -= 1
                j += 1
            inner, suffix = s[i + 1:j - 1], s[j:]
            if i == 0 or inner.startswith('impl '):
                s = _impl_wrapper_type(inner) + suffix
                i = 0
                continue
        i += 1
    out, d, prev = [], 0, ''
    for ch in s:
        if ch == '<':
            d += 1
        elif ch == '>' and prev != '-':
            d = max(0, d - 1)
        elif d == 0:
            out.append(ch)
        prev = ch
    r = ''.join(out)
    r = re.sub(r'::h[0-9a-f]{16}$', '', r)
    r = re.sub(r'\s+', '', r)
    r = re.sub(r':{2,}', '::', r)
    r = r.strip(':')
    # legacy mangling names every closure in a scope the literal
    # placeholder `{{closure}}` (disambiguated only by the mangled name's
    # own hash suffix, already stripped above); v0 mangling/rustc-demangle
    # numbers them `{closure#0}`, `{closure#1}`, ... Same toolchain-drift
    # axis as the impl-wrapper fix above -- collapse to one spelling so a
    # legacy-mangled target's closures match a v0-mangled donor DB's.
    r = re.sub(r'\{closure#\d+\}', '{{closure}}', r)
    return TOOLCHAIN_SYNONYMS.get(r, r)


# std-library internal names that rustc has renamed/reorganized across
# versions, mapped to the older/more widely-recognized form. Found testing
# against real MalwareBazaar samples (compiled with an older rustc than this
# donor corpus): matching against a toolchain-mismatched target, the shipped
# DB's identity for the classic drop shim is the CURRENT nightly's name
# (`core::ptr::drop_glue`), while an older-toolchain target's debug info
# still says `core::ptr::drop_in_place`. Checked against the actual rustc
# source (library/core/src/ptr/mod.rs, compiler/rustc_middle/src/ty/
# instance.rs): these were never two different mechanisms -- drop_in_place
# is `#[inline(always)]` and its whole body is `drop_glue(&mut *to_drop)`,
# and the compiler's synthetic destructor shim has long been represented
# internally as `InstanceKind::DropGlue` with canonical path
# `core::ptr::drop_glue::<T>`. What changed across toolchains is only which
# of the two names gets emitted into the symbol table for an inlined-away
# call site -- same shim, same bytes, different label, so mapping one to the
# other is a correct fix, not a hack. This was 12/17 of the "wrong" matches
# on two real malware samples in that spot check (see ../docs/limits.md §3). Not
# exhaustive -- rustc's std-library internals get reorganized more than
# this single pair (`sys_common::backtrace` -> `sys::backtrace` and
# `sys::unix::args` -> `sys::args::unix` also showed up, unmapped here,
# lower frequency and open-ended to catalog exhaustively).
TOOLCHAIN_SYNONYMS = {
    'core::ptr::drop_glue': 'core::ptr::drop_in_place',
}


# ---------------------------------------------------------------- build / label

def index_binary(path):
    """-> [(hash, n_insns, erased_name, rep_name), ...] for one donor binary,
    Rust-mangled symbols only."""
    fs = read_fdes(path)
    if not fs:
        return []
    h = hash_functions(path, fs)
    nm = symbols(path)
    raw, names_needed = [], set()
    for j, (x, n_insns) in h.items():
        name = nm.get(fs[j].start)
        if name and is_rust_mangled(name):
            raw.append((x, n_insns, name))
            names_needed.add(name)
    dem = demangle(sorted(names_needed))
    return [(x, n_insns, erase_generics(dem.get(n, n)), dem.get(n, n))
            for x, n_insns, n in raw]


def build(paths):
    """{"__meta__": {n_donors}, hash: {name, rep, n_insns, confidence}}.
    confidence = number of distinct donor binaries that independently
    produced this hash with a consistent identity.

    the threshold sweep in ../docs/method.md §6 found confidence as an ABSOLUTE count needs
    re-tuning every time the donor pool grows -- at a fixed min_donor_bins,
    precision *drifts down* as more donors are added (median 87.4% at 32
    donors -> 78.1% at 66, same threshold), because new donors mostly add
    lower-quality newly-confirmed hashes on top of an unchanged high-quality
    core (measured directly: existing matches stayed at
    ~82% precision, the *newly* unlocked ones came in at ~65%), diluting the
    average. A confidence threshold expressed as a FRACTION of the donor
    pool size is pool-size-invariant instead: frac=0.10 gave 87.4% median
    precision at 32 donors and 87.3% at 66 -- see ../docs/method.md §6.
    `label()`'s --min-confidence-frac uses n_donors from here to convert
    that fraction into an absolute count at label time."""
    h2 = collections.defaultdict(list)  # hash -> [(binary, n_insns, erased, rep)]
    if len(paths) > 1:
        from concurrent.futures import ProcessPoolExecutor, as_completed
        # Capped at 4, not os.cpu_count(): some real-world debug binaries are
        # 300-500MB+ (nu, cargo-binstall); each worker holds one in memory.
        # 16-wide and even 8-wide silently died building the shipped DB on a
        # 14GB-RAM desktop already running other things. Widen this if you
        # have the RAM headroom for it -- there's nothing else limiting it.
        with ProcessPoolExecutor(max_workers=min(4, len(paths))) as ex:
            futs = {ex.submit(index_binary, p): p for p in paths}
            for fut in as_completed(futs):
                p = futs[fut]
                rows = fut.result()
                for x, n_insns, erased, rep in rows:
                    h2[x].append((p, n_insns, erased, rep))
                print(f"  indexed {p}: {len(rows)} named functions", file=sys.stderr)
    else:
        for p in paths:
            rows = index_binary(p)
            for x, n_insns, erased, rep in rows:
                h2[x].append((p, n_insns, erased, rep))
            print(f"  indexed {p}: {len(rows)} named functions", file=sys.stderr)
    db = {'__meta__': {'n_donors': len(paths)}}
    for x, obs in h2.items():
        keys = {erased for _, _, erased, _ in obs}
        if len(keys) != 1:
            continue  # ambiguous even within the donor corpus -- drop
        erased = next(iter(keys))
        if is_forwarding_shim(erased):
            continue
        rep = sorted((r for _, _, _, r in obs), key=len)[0]
        db[x] = dict(name=erased, rep=rep, n_insns=obs[0][1],
                      confidence=len({p for p, _, _, _ in obs}))
    return db


def label(db, path, min_confidence=1, min_confidence_frac=None):
    if min_confidence_frac is not None:
        n_donors = db.get('__meta__', {}).get('n_donors', 1)
        min_confidence = max(1, round(min_confidence_frac * n_donors))
    fs = read_fdes(path)
    h = hash_functions(path, fs)
    out = []
    for j, (x, n_insns) in h.items():
        e = db.get(x)
        if e and e['confidence'] >= min_confidence:
            out.append(dict(addr=fs[j].start, size=fs[j].size, n_insns=n_insns,
                             name=e['rep'], identity=e['name'],
                             confidence=e['confidence']))
    out.sort(key=lambda r: r['addr'])
    return len(fs), out, min_confidence


def save_db(db, path):
    """.json.gz path -> gzip-compressed (the shipped DB is ~6x smaller
    gzipped); plain .json -> uncompressed."""
    opener = gzip.open if path.endswith('.gz') else open
    with opener(path, 'wt') as fh:
        json.dump(db, fh)


def load_db(path):
    """Transparent: sniffs the gzip magic bytes rather than trusting the
    extension, so a renamed/redistributed DB still loads."""
    with open(path, 'rb') as fh:
        magic = fh.read(2)
    opener = gzip.open if magic == b'\x1f\x8b' else open
    with opener(path, 'rt') as fh:
        return json.load(fh)


# ---------------------------------------------------------------- CLI

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='mode', required=True)

    b = sub.add_parser('build', help='build a signature DB from unstripped donor binaries')
    b.add_argument('db', help='output DB path (JSON)')
    b.add_argument('binaries', nargs='+', help='unstripped donor binaries (must have symbols)')

    l = sub.add_parser('label', help='label functions in a stripped binary')
    l.add_argument('db', help='DB path from `build`')
    l.add_argument('binary', help='stripped target binary')
    l.add_argument('--min-confidence-frac', type=float, default=0.08, metavar='F',
                    help='require a hash to be confirmed by >=F fraction of the donor '
                         'pool (default 0.08). ../docs/method.md: this is pool-size-invariant, '
                         'unlike an absolute count -- 0.08-0.10 gave 98.1-98.8%% median '
                         'cross-corpus precision on the 110-crate shipped DB (see '
                         'README.md for the full threshold table). Overridden by '
                         '--min-confidence if given.')
    l.add_argument('--min-confidence', type=int, default=None, metavar='N',
                    help='require a hash to be confirmed by >=N distinct donor '
                         'binaries. Overrides --min-confidence-frac; use this only '
                         'if you know your donor pool size and want an exact count '
                         '(e.g. N=1 for max recall, no filter).')
    l.add_argument('--json', action='store_true', help='emit JSON instead of a table')
    l.add_argument('--limit', type=int, default=60, help='rows to print in table mode (0=all)')

    args = ap.parse_args()

    if args.mode == 'build':
        db = build(args.binaries)
        save_db(db, args.db)
        print(f"wrote {args.db}: {len(db) - 1} unambiguous body hashes "
              f"from {len(args.binaries)} donors", file=sys.stderr)

    elif args.mode == 'label':
        db = load_db(args.db)
        if args.min_confidence is not None:
            total, rows, used_conf = label(db, args.binary, min_confidence=args.min_confidence)
        else:
            total, rows, used_conf = label(db, args.binary,
                                            min_confidence_frac=args.min_confidence_frac)
        if total == 0:
            print(f"{args.binary}: no functions found (no .eh_frame/.pdata? "
                  f"not an x86-64 ELF or PE32+?)", file=sys.stderr)
            sys.exit(1)
        if args.json:
            json.dump(dict(binary=args.binary, n_functions=total,
                            n_labeled=len(rows), min_confidence=used_conf,
                            matches=rows), sys.stdout, indent=2)
            print()
        else:
            print(f"{args.binary}: {total} functions, {len(rows)} labeled "
                  f"({100 * len(rows) / total:.1f}% coverage, "
                  f"min_confidence={used_conf})\n")
            print(f"{'addr':>12} {'size':>6} {'conf':>4}  function")
            shown = rows if not args.limit else rows[:args.limit]
            for r in shown:
                print(f"{r['addr']:>#12x} {r['size']:>6} {r['confidence']:>4}  "
                      f"{r['name'][:80]}")
            if args.limit and len(rows) > args.limit:
                print(f"  ... and {len(rows) - args.limit} more (--limit 0 for all)")


if __name__ == '__main__':
    main()
