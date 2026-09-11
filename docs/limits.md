# What limits a body-hash database

Four things, measured. Build configuration, dependency overlap, toolchain drift, and the shape of
the target itself.

## 1. Build configuration has to match on every axis

Two programs, `fsum` (donor) and `vault` (target), share five pinned dependencies: sha2 0.10.9,
aes 0.8.4, walkdir 2.5.0, serde_json 1.0.145 and base64 0.22.1. Their host code differs, and so
does the way each program uses those dependencies: derive-based serde against `Value`
manipulation, concrete `Sha256` and `Sha512` against a generic `fn f<D: Digest>`, standard
base64 against URL-safe base64, and `max_depth` walks against `filter_entry` walks. The resolved
dependency versions were verified identical between the two lockfiles. Both use one pinned
toolchain, 1.97.1 stable.

There are twelve configurations. Each one changes a single factor from the baseline `release,
lto=false, codegen-units=16, opt-level=3, panic=unwind, overflow-checks=off,
target-cpu=generic`, and one further configuration combines them into a "malware profile". Each
`(program, config)` pair was built in its own target directory and removed afterwards. Cargo
does not rebuild dependencies when only the host crate changes, and sharing artifacts between
donor and target makes every number spuriously high. Scoring used `build()`, `hash_functions()`
and `erase_generics()` unmodified. Nothing was tuned.

| single-axis mismatch (donor → target) | third-party match rate |
|---|---|
| *(no mismatch at all)* | *51.9%* |
| `cgu=16` → `cgu=1` | 34.3% |
| `panic=unwind` → `panic=abort` | 29.4% |
| `overflow-checks=off` → `on` | 27.1% |
| `lto=thin` → `lto=fat` | 14.1% |
| `lto=false` → `lto=fat` | 12.8% |
| `opt-level=3` → `opt-level=1` | 10.1% |
| `opt-level=3` → `opt-level=z` | 4.0% |
| `target-cpu=generic` → `native` | 1.1% |

Real Rust malware ships with fat LTO, `codegen-units=1`, `panic=abort` and `opt-level=z`.
Against that profile, a donor built with default `--release` flags scores 5.9%.

LTO is not the mechanism. A fresh build reproduces LTO decisions as long as it uses the same LTO
setting. `fat→fat` scores 53.8% and `lto=false→lto=false` scores 51.9%, which is statistically
indistinguishable (95% Wilson intervals 42.9 to 64.5, and 43.4 to 60.4). What a fresh build
cannot reproduce is an *unknown* configuration, and every axis tested is about as destructive as
LTO.

Normalisation does tolerate more than a byte pattern does, and that shows up as roughly 100%
naming precision in every cell that matches anything at all. It does not tolerate a one-flag
difference.

This is the basis for [`method.md`](method.md) §4. An indexed donor binary carries the target's
whole build configuration implicitly, across all six axes. A recompiling tool has to guess it.
LTO is one of the six. The measured LTO stratification in [`benchmark.md`](benchmark.md) is
unaffected, but its explanation changes.

### At scale, and on a second pair

Replicated with 25 shared crates instead of 5, at 3 to 13 times the per-cell n:

- Third-party diagonal, 25 headline crates: median 52.6% (range 51.2% to 59.3%).
- All third-party including transitive: median 69.5%.
- Naming precision on the diagonal: 99.4%.
- One flag off: 1% to 35% pooled, and 0.0% by per-crate median. A few large crates
  (`regex_automata`, `aho_corasick`) carry the entire pooled off-diagonal number, while most
  crates get nothing.
- Malware profile against a default-release donor: 2.1%.

A second independent donor/target pair scores 44.7% on its own designed pairing. That is inside
the predeclared 40% to 70% band, but below the first pair's observed range. Cross-substituted
donors do **not** score lower than matched pairs. They score 5 to 13 points *higher* in both
directions:

| donor ↓ / target → | `beacon` | `vaultpack` |
|---|---|---|
| `harvest` | 51.8% (designed pair) | **57.2%** (cross) |
| `logship` | **56.8%** (cross) | 44.7% (designed pair) |

Both cross cells outscore both designed-pair cells, which is the opposite of what "cross-program
body divergence is the limiting factor" predicts. Combining two donor programs adds +0.9pp
against one target and +6.4pp against the other.

The negative control holds throughout: a third program linking none of the shared dependencies
produces 2 matches in 637 functions, both the known case of `memchr` being vendored into std, and
0 genuine false positives.

## 2. Coverage is dependency overlap

Three controls, on the question of what actually moves coverage.

Build environment and toolchain are not the limit. This is one program, built twice
independently, scored against one database:

| target | functions | named | coverage | precision |
|---|---|---|---|---|
| ripgrep, corpus build (same pipeline as DB) | 8,790 | 4,028 | 45.8% | 94.5% |
| ripgrep, different machine, rustc about 6 releases newer | 8,959 | 3,990 | **44.5%** | **94.1%** |
| hexyl, same different-machine build | 1,309 | 86 | **6.6%** | 30.2% |

Rebuilding ripgrep elsewhere on a much newer toolchain cost 1.3 points of coverage and 0.4 of
precision. n=1, and it is a claim about coverage only.

Dependency overlap is the limit. hexyl collapses to 6.6% in the same experiment where ripgrep
holds 44.5%, built the same way by the same script minutes apart. hexyl is small (1,309 functions)
and shares few crates with the database. ripgrep shares `regex`, `ignore`, `globset`, `clap` and
`memchr` with `fd` and the others.

| you have | coverage | precision |
|---|---|---|
| donors sharing the target's dependencies | 45% to 75% | about 99% |
| std-only database, same toolchain era | about 29% | about 99.7% |
| toolchain rlibs only, zero build cost | about 4% | high |
| small target, unfamiliar dependencies | about 7% | low and noisy |
| real malware (small, unlike the donor pool) | about 0.3% | 80% to 95%, n=2 |

Donor breadth improves three things at once: coverage, precision at a fixed confidence fraction,
and the precision floor. It also saturates. Holding one target fixed and growing the donor set
gives 1 donor 5.5%, 2 donors 15.8%, 3 donors 20.6%, 5 donors 28.7%, 8 donors 30.5%, 13 donors
32.2%. Mostly saturated by 8 for a target whose workload is unlike the donor set.

Same-corpus provenance is not the explanation either. This is leave-one-out inside a second
corpus, holding toolchain, build method and source provenance fixed, measured against the
13-donor set on the same targets:

| target | donors = the 13 | donors = same-corpus LOO (4) |
|---|---|---|
| ast-grep | 28.4% | **56.3%** |
| starship | **20.2%** | 15.8% |
| trippy | **32.2%** | 11.8% |
| wiki-tui | 18.1% | 19.5% |
| zellij | **13.8%** | 9.5% |

No consistent within-corpus advantage. What fits is that 13 diverse CLI tools collectively
instantiate more of std than 4 binaries do. Toolchain matching governs whether a body matches
once you have it; donor breadth governs whether you have it at all, and with small donor sets
breadth dominates.

## 3. std changes faster than malware is rebuilt

Same program built with 5 rustc toolchains, comparing std function bodies by generic-erased path:

| | 1.88 | 1.90 | 1.91 | 1.93 | 1.97.1 |
|---|---|---|---|---|---|
| **1.88** | 100% | 60.6% | 42.6% | 28.1% | 20.4% |
| **1.90** | | 100% | 69.1% | 40.4% | 23.2% |
| **1.91** | | | 100% | 49.2% | 24.2% |
| **1.93** | | | | 100% | 56.9% |

Adjacent releases share 49% to 69% of std bodies. 1.88 to 1.97 keeps 20.4%.

Mangled symbol names cannot be compared across toolchains at all. They embed a per-compilation
disambiguator hash, so name-keyed matching finds zero overlap. The comparison has to run on
generic-erased demangled paths.

That churn does not propagate end to end, because third-party crate code carries the coverage and
is stable as long as the crate versions line up. It is why the std-only floor is quoted for a
toolchain *era* rather than universally.

### Names do not survive drift, even where coverage does

On real ransomware samples (static analysis only, nothing executed), raw precision at the shipped
database's default confidence measured 48% to 50%. The wrong matches were checked longest first,
because a long-function collision is implausible as an accident. That produced an immediate
pattern:

```
pred = core::ptr::drop_glue                truth = core::ptr::drop_in_place    (x12)
pred = std::sys::backtrace::__rust_begin_short_backtrace
      truth = std::sys_common::backtrace::__rust_begin_short_backtrace          (x1)
pred = std::sys::args::unix::imp::ARGV_INIT_ARRAY::init
      truth = std::sys::unix::args::imp::ARGV_INIT_ARRAY::init                  (x1)
```

Traced through the samples' embedded `/rustc/<commit>/` panic-location strings: the malware was
compiled with rustc commit `79e9716c`, every donor with one local nightly `9e2abe0c` (1.98.0-
nightly). Between those points rustc renamed the compiler-generated destructor shim from
`core::ptr::drop_in_place` to `core::ptr::drop_glue` and reorganised two more module paths.

14 of 17 wrong matches (82%) were toolchain drift, 12 of them the `drop_glue` pair alone. Only 3
were genuine short-code collisions.

Confirmed against rustc source rather than left as a correlation: `library/core/src/ptr/mod.rs`
shows `drop_in_place` is `#[inline(always)]` and its entire body is `drop_glue(&mut *to_drop)`,
and `compiler/rustc_middle/src/ty/instance.rs` shows the synthetic destructor shim has long been
`InstanceKind::DropGlue` with canonical path `core::ptr::drop_glue::<T>`. Same shim, same bytes,
different label. That is why mapping one name to the other is a correct fix rather than a hack,
and it is the bar for adding any future synonym.

| sample | before | after | remaining errors |
|---|---|---|---|
| Akira | 13 correct / 14 wrong (48.1%) | **39 / 2 (95.1%)** | the two unmapped module renames |
| BlackCat | 3 / 3 (50.0%) | **12 / 3 (80.0%)** | genuine short-code collisions |

Read the counts, not the percentages. Scored functions went 27 → 41 and 6 → 15. The synonym is
applied symmetrically at build and label time, so mapping it did not merely re-classify
already-scored functions. It brought functions into scope that previously had no comparable
identity on one side. The before and after percentages are over different sets.

n=2 distinct codebases, not n=2 samples: a third sample with a different sha256 gave identical
correct/wrong counts and identical wrong examples, almost certainly the same ransomware-as-a-
service build shared across affiliates, and is reported as one data point.

The systematic fix would be donor diversity across toolchain eras rather than an ever-growing
synonym table. Tested once: 15 crates rebuilt with `cargo +stable install`, folded into a
125-donor database (+19,981 unique hashes, genuinely new content). Precision and wrong-example
lists were unchanged; stripped-sample coverage moved by one function. A real negative at that
scale, and a weak test rather than a refutation.

## 4. What rustc built the malware

730 distinct samples from fifteen ransomware and loader families, ELF and PE, x86-64 and x86.
Compiler version read from the build hash rustc embeds in panic-location paths
(`/rustc/<hash>/`), mapped to a release via the public list of nightly and release commits, and
failing that from the version string in the ELF `.comment` section.

- 460 carry a recoverable compiler version. Those span **rustc 1.46 (2020) through 1.92 (December
  2025)**, which is 25 distinct point releases.
- The remaining 230, nearly all one family, strip every version marker and can only be bracketed
  by build structure.
- Four out of five dated builds came from a nightly compiler, not a release. Two nightly pins
  alone account for seventy percent of them.
- Families cluster: most pin one or two compilers and reuse them across dozens or hundreds of
  builds.

Combined with §3, this sets the storage cost of keeping a database current. std is about 29% of
a stripped Rust binary. A donor set built at version *V* retains 49% to 69% of std bodies one
release away, and about 20% nine releases away. A database is therefore useful within about one
release of the target's toolchain. Covering the observed range is a fixed, linear amount of storage per rustc
release, not a one-time build.

## Reproducing

```sh
python3 bench/scripts/grow_corpus.sh          # donor set, debug info forced on
python3 bench/scripts/build_index.py          # cache raw per-donor rows
python3 bench/scripts/evaluate.py             # coverage / precision / library recall
python3 bench/scripts/frac_confidence_exp.py  # the confidence-fraction sweep
```

The index cache stores raw per-donor rows (hash, instruction count, erased identity,
representative name) rather than a built database, so any filtering configuration can be built
from one disassembly pass. A 200-point threshold sweep over both target sets takes
about two minutes instead of an hour, which is the only reason nine iterations of precision work
were affordable.
