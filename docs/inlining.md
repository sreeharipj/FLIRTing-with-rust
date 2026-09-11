# The function is the wrong unit

FLIRT and rustsig both match whole functions. Library code the compiler inlined away has no
function to match. This measures how much that costs, and whether anything can be done about it.

Every number here is within one corpus: 13 donors off one build pipeline with one toolchain. The
cross-corpus equivalent has not been run. Nothing here is wired into `rustsig.py`.

## The census

Parse `DW_TAG_inlined_subroutine` out of each donor's DWARF twin, push both the concrete
subprogram names and the inlined-callee names through rustsig's own demangle and generic erasure,
and compare the two identity sets. `bench/scripts/extract_inline.py`.

| binary | identities as functions | identities inlined | inlined with no standalone copy | inline instances |
|---|---|---|---|---|
| bat | 2062 | 6959 | 6664 (95.8%) | 205,023 |
| dust | 1450 | 5508 | 5278 (95.8%) | 136,641 |
| fd | 1695 | 5897 | 5646 (95.7%) | 172,994 |
| grex | 1529 | 4863 | 4625 (95.1%) | 114,839 |
| hexyl | 662 | 2630 | 2541 (96.6%) | 65,850 |
| hyperfine | 809 | 3468 | 3377 (97.4%) | 70,047 |
| just | 1991 | 6919 | 6619 (95.7%) | 237,682 |
| pastel | 652 | 3031 | 2942 (97.1%) | 59,987 |
| ripgrep | 2785 | 5818 | 5520 (94.9%) | 175,849 |
| sd | 1216 | 4603 | 4432 (96.3%) | 109,484 |
| tokei | 2117 | 6661 | 6339 (95.2%) | 182,821 |
| xsv | 1178 | 3771 | 3642 (96.6%) | 99,805 |
| zoxide | 672 | 2974 | 2889 (97.1%) | 58,855 |
| **mean / pooled** | **1448** | **4854** | **4655 (95.9%)** | **1,689,877** |

95.9% of the distinct library identities physically present in a default `--release` binary exist
only as inlined code. The addressable universe for a whole-function matcher is the other 4.1%, a
factor of roughly 24 in identity count.

By volume the picture is less extreme: 35.2% of named `.text` is owned by an identity with no
standalone copy, with pastel the corpus maximum at 44.5%. An earlier version of this figure read
60.1% and was inflated by an extractor bug: 999 instances corpus-wide whose byte length equalled
their start address. The identity counts above do not use that field and are unaffected.

Every DWARF-derived count is a lower bound. Instances expressed with `DW_AT_ranges` rather than
`low_pc`/`high_pc` are skipped. Tombstoned DIEs are excluded as dead. Those are DIEs at address
0, debug info for code the linker discarded, and they are 48.4% of instances in a `cgu=16`
non-LTO build and 0.05% under fat LTO.

## Do inlined fragments reproduce across binaries?

The objection that could have ended this: an inlined body is optimised jointly with its host, so
register allocation and scheduling should differ per call site and no two copies should ever hash
alike.

Of identities inlined in 2 or more donors, the share whose body hash is reproduced in 2 or more
donors, under rustsig's unmodified token alphabet:

| min instructions | confirmable identities | reproduced | rate | instance-level |
|---|---|---|---|---|
| 4 | 4840 | 3665 | 75.7% | 58.1% |
| 8 | 2974 | 2232 | 75.1% | 53.1% |
| 16 | 1594 | 1151 | 72.2% | 46.6% |
| 32 | 756 | 526 | 69.6% | 46.6% |
| 64 | 308 | 217 | 70.5% | 55.2% |

Softening the alphabet buys 5 to 7 points at identity level, whether by dropping register
identity or by going mnemonic-only, so the alphabet stays as it is. Reproducibility falls as fragments get longer,
which is the expected sign: a longer fragment has more surface to be perturbed.

An inlined fragment essentially never equals a standalone function body. Cross-binary, 0.10% of
instances and 0.3% of identities at minimum length 8. Prologue, epilogue and frame setup are what
inlining removes. The shipped whole-function database cannot be reused by scanning; a fragment
database has to be built separately, and the donors already carry the DWARF to build it.

## The nested-chain artifact

The first fragment database looked mediocre: 36.7% of fragment hashes mapped to more than one
erased identity and were dropped, leaving 6,581 usable signatures.

Reading the ambiguous clusters showed what they were:

```
1879 instances -> {&alloc::alloc::Global::deallocate, __rustc::__rdl_dealloc,
                   alloc::alloc::Global::deallocate}
 972 instances -> {alloc::alloc::Global::deallocate, ::deallocate_impl,
                   ::deallocate_impl_runtime}
```

Not collisions. When A inlines B inlines C and all three occupy the same address range, DWARF
records three instances over one range and the range picks up every identity in the chain. The
ambiguity is manufactured by the extraction.

Keeping only the outermost identity per `(host, lo, len)` range:

| | ambiguous | usable signatures | identities | leave-one-out coverage | precision |
|---|---|---|---|---|---|
| raw, every nesting level | 36.7% | 6,581 | 1,085 | 18.6% | 100.0% |
| chain-collapsed | 0.8% | 10,414 | 1,624 | 49.2% | 99.9% |

Leave-one-out over 13 donors, fragments of 8 instructions or more: median 49.2% of inlined
instances named at 99.9% precision, a median 683 distinct identities per target. The
whole-function baseline on the same harness is 46.6% coverage at 99.7% precision.

## Without DWARF on the target

Every number above assumed oracle boundaries: the target's own DWARF told the harness where each
inlined range started and ended. A stripped target does not know that. If boundary discovery is
intractable, or if scanning every window drowns the result in false positives, none of the rest
matters.

The scan indexes each signature by a prefix hash over its first 4 tokens, walks every instruction
position in every `.eh_frame` function, and at each position hashes only the window lengths that
some signature with that prefix actually has. `bench/scripts/scan.py`, 13-donor leave-one-out,
database built from the other 12.

A hit is **correct** if the window is exactly a DWARF inlined instance and the identity matches,
**mislabelled** if it is exactly an instance with the wrong identity, and **unconfirmed** if it is
not a DWARF instance boundary at all. Unconfirmed hits could be real inlines DWARF did not
record; they are counted against the method regardless.

| min instructions | median correct | median mislabelled | precision on confirmed | median identities named | median windows hashed |
|---|---|---|---|---|---|
| 16 | 97.5% | 0.0% | 100.0% | 319 | 26,361 |
| 8 | 91.0% | 0.0% | 99.9% | 683 | 46,710 |

Worst target of 13 is tokei at minimum length 8: 84.6% correct, 2.3% mislabelled. Best is 98.2%
correct, 0.0% mislabelled.

Boundary discovery is not the obstacle. The prefix index prunes a nominal 10⁷-window search to
about 5×10⁴ hashes per binary, and what survives lands on a true inline boundary 91% to 97.5% of
the time. The identity yield also beats the whole-function database on the same corpus: a median 683
identities named per target against roughly 600 for whole functions, on a population whole-
function matching structurally cannot reach.

### `.eh_frame` does not mark inline boundaries

`.eh_frame` already bounds the scan, since the function list comes from it. The question is
whether it carries anything inside a function that marks an inlined boundary. The only
per-address structure it has is the CFI row table. Measured on pastel:

| | |
|---|---|
| FDEs | 1,056, mean 8.3 CFI rows each (median 6) |
| interior CFI row addresses (not a function start) | 7,715 |
| DWARF inlined-instance starts | 23,785 |
| inline starts that are also a CFI row | 202, a recall of 0.8% |
| interior CFI rows that are an inline start | 130, a precision of 1.7% |

Both directions fail, and the mechanism says they should: CFI rows track prologue and epilogue
frame setup, and inlining a callee normally folds into the host's existing frame without changing
it. `.eh_frame` gives function bounds and nothing finer. It does not matter, because the prefix
index solves boundary discovery without an anchor.

### The anchor that probably does work

unhusk locates author code with `core::panic::Location` metadata rather than `.eh_frame`, and that
data survives stripping. In `pastel.stripped`:

```
116 source-path strings, 12 crate-version strings, e.g.
  .../registry/src/index.crates.io-.../clap_builder-4.5.60/src/builder/arg.rs
  .../registry/src/index.crates.io-.../anstream-0.6.20/src/adapter/strip.rs
```

Each is a `Location` record in `.rodata` referenced by the code that can panic there. The address
referencing it says that instruction came from `clap_builder-4.5.60/src/builder/arg.rs` line N,
even when that code was inlined into an unrelated function, with crate, version, file and line
attached, and needing no donor corpus. That is a per-crate anchor with an identity, which is more
than a boundary.

Untested. How many inlined instances sit near a `Location` reference, and whether nearest
preceding `Location` predicts the enclosing inlined callee, are open questions.

## What the misses actually are

Setup: a donor/target program pair with 25 shared pinned dependencies, rebuilt at `base`,
`lto-fat` and `optz`, toolchain 1.97.1. Sanity check first: the `base→base` third-party function
match rate reproduces at 52.5% against the 51.8% measured previously.

The first classification bucketed every non-match as "bytes differ" and reported 56.1% of misses
in that class. A similarity probe on those pairs returned median token similarity 1.00: the two
bodies were identical. A class labelled "bytes differ" whose members have identical bytes is a
classification error, not a result. Corrected, splitting on hash presence before anything else:

| matched-flag miss cause | all identities | third-party |
|---|---|---|
| body is byte-identical in the donor, but its hash carries more than one identity, so `ambiguity ⇒ drop` discarded it | **77.1%** | **51.4%** |
| hash present under a different single identity (real collision) | 0.1% | 0.0% |
| hash absent, inlined-callee multiset differs (true inlining divergence) | 17.2% | 24.3% |
| hash absent, same inlined-callee multiset (other codegen divergence) | 5.6% | 24.3% |

Cross-program body divergence is 22.8% of misses. The tool's own conservatism is 77.1%. An
earlier attribution of the diagonal ceiling to "cross-program body divergence" does not survive
this decomposition.

The shape of that ambiguity, over the 13-donor corpus:

| | whole functions | fragments (minlen 8, raw) |
|---|---|---|
| hashes that are ambiguous | 3.5% | 36.7% (0.8% chain-collapsed) |
| colliding identities: median / p90 / max | 2 / 6 / 116 | 2 / 5 / 29 |
| all colliding identities share the same crate | 55.3% | 40.3% |
| all colliding identities share the same method name | 51.7% | 13.7% |
| either one, so a coarser label is still exact | **84.8%** | 48.2% |

Examples at scale: `{&str::type_id, ()::type_id, Box::type_id}` (481 instances),
`{Box::cause, Box::source}` (198), `{String::write_fmt, anyhow::Quoted::write_fmt,
anyhow::Indented::write_fmt}` (153).

## Does sub-function granularity beat the configuration wall?

No. Fragments are better in every cell, and notably safer off-diagonal where whole-function
precision collapses, but the diagonal/off-diagonal contrast is unchanged.

| donor → target | fn rate | fn prec | frag rate | frag prec |
|---|---|---|---|---|
| base → base | 77.7% | 100.0% | 89.3% | 99.9% |
| base → lto-fat | 8.0% | 96.2% | 14.5% | 96.3% |
| base → optz | 9.4% | 95.7% | 29.3% | 99.9% |
| lto-fat → base | 6.9% | 86.8% | 13.7% | 98.8% |
| lto-fat → lto-fat | 81.8% | 99.9% | 80.8% | 99.9% |
| lto-fat → optz | 2.4% | 48.4% | 8.3% | 98.8% |
| optz → base | 16.3% | 98.4% | 15.6% | 98.9% |
| optz → lto-fat | 3.5% | 88.1% | 4.5% | 94.1% |
| optz → optz | 77.3% | 99.8% | 89.2% | 100.0% |

## Two changes this points to

### Emit the common denominator of an ambiguous hash

77.1% of matched-flag misses are byte-identical bodies discarded by `ambiguity ⇒ drop`, and 84.8%
of ambiguous whole-function hashes have all their colliding identities sharing a crate or a
method name. That denominator is a label such as `alloc::*` or `*::fmt`. Emitting it as its own
output class is strictly additive, since those functions are UNKNOWN today, and it moves them
into LIBRARY for triage. It needs its own metric:
scoring a set-label against an exact-identity ruler repeats the conflation error above, so score
it as whether the true identity is a member of the emitted set and report it separately.

### Build the fragment database

Every internal test passes and all of them are within-corpus. The cross-corpus run against
held-out targets is the gate, and it should be predeclared: a bar for fragment naming precision,
decided in advance, that decides whether the subsystem ships.

One argument this strengthens: an inlined fragment can only be harvested from a linked binary. It
does not exist in an rlib and a recompiling tool cannot manufacture it.

The engineering hazard to design against: the donor side reads DWARF ranges and the target side
runs a blind scan. Those are structurally different code paths that must produce byte-identical
hashes, which is exactly the asymmetry that produced the `PYTHONHASHSEED` silent-0% bug in the
main tool. One shared tokeniser for both paths, plus a test that hashes the same range both ways
and asserts equality.

## Limits of these numbers

- The census and reproducibility results are within-corpus. All 13 donors come off one build
  pipeline with one toolchain. This is a ceiling measurement, not a cross-corpus test.
- The miss autopsy is one program pair, three configurations of twelve.
- The "same inline multiset, bytes differ" bucket is n=42. Its profile indicates many small
  scattered edits rather than one splice: median token similarity 0.97, longest single common run
  only 0.76 of the shorter body, and 4.8% of pairs with one run ≥0.95. That rules out content-defined
  chunking and single-insertion models. It does not support a positive claim about shingle-based
  matching.
- Every DWARF-derived count is a lower bound.
