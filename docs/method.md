# rustsig method

Given a stripped x86-64 Rust ELF with no symbol table and no DWARF, decide for each function
whether it is library code and which library function it is.

## The enabling measurement

FLIRT's known weak spot in Rust is monomorphized generics: `Vec<Foo>::push` and `Vec<Bar>::push`
are different code at different addresses in every binary. The untested question was whether a
*normalised* body hash of a monomorphized instantiation reproduces across independently built
binaries.

Measured over 10 binaries, on the 1,141 symbols appearing in at least 2 of them:

| | cross-binary hash stability |
|---|---|
| all shared symbols | 94.1% |
| plain functions | 91.2% |
| generic instantiations | 99.1% |

Generic instantiations are the most stable category under normalisation and the least stable
under raw byte matching.

## Pipeline

Build, from unstripped donors: `.eh_frame` FDEs → normalised body hash → `nm` symbols filtered to
Rust-mangled → demangle → erase generics → identity string → database entry keyed by hash.

Label, on a stripped target: `.eh_frame` FDEs → normalised body hash → database lookup →
confidence floor → name.

Both sides run the identical boundary and hashing code. Any asymmetry in how a donor body and a
target body get hashed surfaces as a silent 0% match rate, not as an error.

## 1. Boundaries

`.eh_frame` is an allocated section required for unwinding, so it survives `strip --strip-all`.
Each FDE gives `[start, end)`. Measured on one binary: 612 of 612 function ranges identical, byte
for byte, between the stripped and unstripped copies.

Failure modes are explicit. No `.eh_frame` means no functions and no output. `panic = "abort"` and
`-C force-unwind-tables=no` builds may thin the section out. Real malware sometimes ships a
truncated section header table; pyelftools raises from inside header parsing rather than
signalling "no info", so the reader catches broadly and reports the binary as not analyzable.

## 2. Normalised body hash

Disassemble each `[start, end)` with capstone, emit one token per instruction, join, blake2b-128.
Mask exactly what differs between two independently linked copies of the same item, and nothing
else.

| operand | treatment | why |
|---|---|---|
| mnemonic | kept | the shape of the computation |
| register operands | kept | register allocation is deterministic per body |
| branch and call target immediates | masked | link-time addresses |
| immediates inside the `.text` range | masked | materialised code addresses |
| other immediates | kept | constants are signal |
| RIP-relative memory | masked | `.rodata`/`.data` displacement is link-dependent |
| other memory operands | kept | stack layout distinguishes real functions |

Tokens come from decoded operands, not printed text; printed text carries symbolisation and
formatting differences.

Two consequences. The hash generalises across builds, because everything relocation-dependent is
gone. And it cannot distinguish two functions that differ only in what they call, because the
call target is the masked field. Section 5 is the fallout from the second.

The digest must be stable across processes. The first version used Python's builtin `hash()`,
which is per-process salted: every in-process experiment was self-consistent and correct, and a
database built in one run matched nothing in another. The symptom was a silent 0%.

## 3. Generic erasure

```
<Vec<u8> as Drop>::drop::h0123456789abcdef   →   alloc::vec::Vec::drop
```

| question asked | coverage | precision |
|---|---|---|
| which exact symbol? | 21.9% | 77.8% |
| which function, generics erased? | 21.9% | 99.1% |

`drop_glue<Vec<A>>` and `drop_glue<Vec<B>>` compile to identical bytes. Filtering by instruction
count does not separate them: precision stays near 77% from 0 to 100 instructions, so this is not
a short-function artifact.

The implementation is string normalisation. Every clause was added to fix a measured collision
cluster:

| normalisation | why it exists |
|---|---|
| depth-tracked `<...>` erasure | the base operation |
| strip trailing `::h[0-9a-f]{16}`, collapse `::{2,}` | symbol-table names carry the legacy hash suffix after the generic block; DWARF names never had one |
| unwrap `<SelfType as Trait>::method` → `SelfType::method` | discarding the wrapper lost the type name |
| unwrap it mid-string, not only leading | legacy mangling encodes an impl block by where it was written: `anyhow::context::<impl Debug for anyhow::error::ContextError<C,E>>::fmt` against v0's `anyhow::error::ContextError::fmt` |
| turbofish guard | "preceded by `::`" also matches `drop_in_place::<Foo>`; the unguarded version raised one target's wrong-match count from 94 to 159, the guarded one dropped it to 20 |
| `{closure#N}` → `{{closure}}` | legacy names every closure in a scope the same, v0 numbers them |
| toolchain synonyms | see [`limits.md`](limits.md) |

The database also filters to Rust-mangled symbols only. Donor crates statically link C and asm
libraries; `xh` alone contributes 2,219 of 15,240 symbols from aws-lc and oniguruma. Those are
short byte-identical trampolines with no Rust identity to offer. Matching them is FLIRT's home
turf and FLIRT is corpus-independently good at it.

## 4. Donor binaries rather than recompiled crates

RIFT detects the target's crate and rustc versions and recompiles them. rustsig indexes
already-linked binaries, whose entries were produced by real links with whatever flags the builder
used.

An indexed binary carries the target's build configuration implicitly. A recompiling tool has to
reconstruct it. LTO is one coordinate of that configuration rather than the mechanism;
[`limits.md`](limits.md) gives the boundary of this argument.

The same choice produces a clean negative. Indexing rustup's shipped `.rlib`s gives a
version-exact database at zero build cost, and 4.3% coverage, because monomorphized generics are
not in the rlib — `Vec<Foo>::push` is instantiated in the user's compilation. A database that
wants generic coverage has to come from linked binaries.

`nm` cannot read modern std rlibs at all; binutils' gold LTO plugin fails on LLVM 21 bitcode.
Parse the ELF symbol table directly.

## 5. Database construction

Three rules.

**Ambiguity drops the entry.** If donors disagree on the erased identity for one hash, the entry
is discarded rather than guessed. This is where the precision comes from, and it is not cheap:
77.1% of matched-flag misses are byte-identical bodies discarded by this rule.
[`inlining.md`](inlining.md) covers what to do about that.

**Forwarding shims drop, about 3.6% of entries.** `library/core/src/fmt/mod.rs`'s `fmt_refs!`
macro generates `impl<T: Debug> Debug for &T { fn fmt(&self, f) { Debug::fmt(&**self, f) } }`, and
the same for `&mut T` and seven more traits. The body does not depend on the concrete type beyond
which function it calls next, and the call target is masked, so every instantiation for every `T`
hashes identically. One binary contains 1,134 such symbols. `Box`, `Rc`, `Arc` and `Weak` use the
same idiom for `Debug`, `Display`, `PartialEq`, `PartialOrd`, `Ord` and `Hash`.

The filter cannot detect body shape, because masking already removed the distinguishing field. It
recognises the donor's identity by name and refuses to trust it at any confidence. `Clone` was
checked and deliberately excluded: `Box::clone` pre-allocates and calls `clone_to_uninit`, which
is more than a masked-identical forward. The method list is curated per type rather than blanket.

Measured before shipping, on 5 cross-corpus targets: median precision 93.3% → 95.6%, floor 85.8%
→ 91.1%, recall cost 0.3–2.4pp. The filter runs at database-build time, so an old database used
with new code is not fixed.

**Confidence counts distinct donor binaries, not occurrences.**

## 6. Confidence as a fraction of the pool

At a fixed absolute threshold, precision drifts down as the donor pool grows:

| min donor bins | 32 donors | 66 donors | 110 donors |
|---|---|---|---|
| 1 | 78.8% prec / 19.3% rec | 75.9% / 24.6% | 75.3% / 25.1% |
| 3 | 87.4% / 9.5% | 82.1% / 10.9% | 79.1% / 11.7% |
| 5 | 89.5% / 6.7% | 85.0% / 9.3% | 83.6% / 10.4% |

Comparing every match at `bins=3` between the 32- and 66-donor databases, zero previously-correct
matches flipped to wrong. Growth is additive. But matches newly unlocked by the extra donors came
in at 64.7% precision against the existing core's 81.6%. A larger pool does not corrupt what
worked; it stacks lower-average-quality matches under a fixed bar.

A relative bar is pool-size invariant, and its floor rises as the pool grows:

| `--min-confidence-frac` | median naming precision | floor (worst of 5) | median library recall |
|---|---|---|---|
| 0.03 | 98.6% | 97.8% | 14.7% |
| 0.05 | 98.8% | 98.4% | 12.7% |
| 0.08 (default) | 99.1% | 98.7% | 12.0% |
| 0.10 | 99.2% | 98.7% | 11.6% |
| 0.15 | 99.2% | 98.7% | 9.9% |

The same table at 32 donors reads 87.5% median and 85.2% floor at 0.08. The fraction holds the
knob stable while the pool grows; the pool growth raises the floor.

`--min-confidence N` overrides with an absolute count. `N=1` is the max-recall "is this library
code at all" mode, for elimination rather than naming.

## 7. Composition with unhusk

[`unhusk`](https://github.com/sreeharipj/unhusk) finds author code from `core::panic::Location`
metadata: 98.5% precision, low recall. rustsig finds library code at higher recall and slightly
lower precision. `triage.py` buckets every function as `AUTHOR`, `LIBRARY` or `UNKNOWN`.

unhusk wins ties. Where the two disagreed on ripgrep, all 5 contradictions were rustsig's errors.

Measured on a `strip --strip-all`ed ripgrep with a database built from 9 other binaries: 4,932
functions to read instead of 8,790, a 44% reduction, retaining 91.6% of author code.

## 8. Validation

Four evaluations at increasing distance from the donor corpus.

| | establishes | result |
|---|---|---|
| within-corpus leave-one-out | the primitive works | 62.1% coverage / 99.0% precision, 6 targets |
| std-only database | what works with no knowledge of the target's dependencies | 29.2% coverage / 99.7% precision, 5 targets |
| paired head-to-head | comparison against the incumbent | [`benchmark.md`](benchmark.md) |
| cross-corpus held-out | the naming generalises | 99.1% median / 98.7% floor, 5 targets |

Held-out targets are enforced at the source-scan level, not only by the target list, so a
corpus-growth script cannot leak a test target into the donor pool.

std-only precision is higher than a full database's, 99.7% against 98.6%. Third-party crates
introduce version skew, where two versions of a crate compile to the same body under different
names. std is pinned by the toolchain and mostly does not.

The cross-corpus number started at 33–53%. Nine findings moved it: donor breadth had only been
tested against coverage and moves precision too; the database was absorbing statically-linked
C/asm symbols; two `erase_generics` string bugs were scoring correct matches as collisions; an
absolute confidence threshold does not scale with pool size; the donor corpus was built with one
week's bleeding-edge nightly; the forwarding-shim family, then each half of it; and the
impl-wrapper unwrap firing only when leading.

## 9. Hazards

Each of these produced a plausible-looking wrong number rather than an error.

- The evaluation harness shares `erase_generics` with the tool. A bug that maps both sides the
  same way is invisible and harmless. A bug that maps them differently — which is what happens
  when one side comes from a symbol table and the other from DWARF, or one is v0-mangled and the
  other legacy — scores correct matches as collisions. Two of the nine findings were this. The
  symptom is always that precision is lower than it should be.
- Long wrong matches are the diagnostic. A 300-instruction function is not an accidental
  collision. Every precision finding came from sorting wrong matches by length descending and
  reading the top.
- A pre-ship spot check caught a regression the aggregate hid: a fix that improved the median
  raised one target's wrong-match count from 94 to 159.
- Rulers are code. A separate line of work in this project found its ground-truth loader was
  mislabelling symbols, which had been distorting every number downstream for several rounds.

## 10. Rejected: call-graph consistency

Resolve each function's unmasked call targets, get first-pass identities for them, and flag
matches whose expected callees do not overlap what the target actually calls.

Implemented and tested. It works as hypothesised on one target (71.4% precision on disagreements
against 92.3% on agreements) and inverts on the target that most needed it. Disagreement samples
are tiny everywhere (n=8, 14, 1). Not integrated: the signal does not reliably point the right
direction on the case it was built to fix, and it costs a full donor symbol-table demangle plus a
two-pass `label()`.
