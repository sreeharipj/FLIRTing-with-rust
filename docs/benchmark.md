# How much of a Rust binary does FLIRT name?

The measurement, and the harness bug that made the first version of it wrong in our favour.

## Setup

The binaries are 13 real Rust CLI tools, each as a `.stripped` file with a DWARF `.debug` twin.
Neither tool ever sees the twin; it is only the ruler's source. Nine were built with LTO, four
without.

The ruler is [`unhusk`](https://github.com/sreeharipj/unhusk)'s DWARF oracle. For each function
it says whether the code is author code or library code, and which library. RIFT's own benchmark
uses the same oracle.

The FLIRT side is [RIFT](https://github.com/microsoft/RIFT) end-to-end, not a re-implementation.
RIFT resolves the target's rustc version from the build hash, installs that toolchain, recompiles
the dependency crates, and emits FLIRT signature files. radare2's `zfs` applies them. RIFT
resolved `nightly-2026-04-22` for every binary, and signature counts run 12 (zoxide) to 50 (bat).

The metric is `library_matched / n_truth_library`, which is RIFT's own definition. Denominators
were verified equal between the two pipelines on every binary. Any mismatch was dropped rather
than reported.

The function universe is the `.eh_frame` FDEs from the stripped binary. This matters more than
anything else here, as the next section shows.

## The correction

The harness this started from built its radare2 command list as `["aaa"] + [zfs ...] + ["aflj"]`.
`zfs` matches only against functions radare2 has already created, so `aaa` silently defined
FLIRT's candidate set. The scorer then divided by the whole `.eh_frame` universe, and the
comparison tool was handed that whole universe directly.

`aaa` reaches a median of **59.4%** of the FDE function universe. So FLIRT was scored against
every function and shown 59% of them.

A positive control settles where the loss is. Take a binary built with `1.90.0` and match it
against RIFT's own `rustc-1.90.0` signature. That signature comes from the very sysroot rlibs the
binary links, so the bytes are identical by construction and every miss belongs to the applier:

| input | r2 functions | pattern-backed found by r2 | FLIRT-named | **of those r2 found** |
|---|---|---|---|---|
| unstripped, 1 sig | 814 | 621 / 621 (100%) | 597 | **96.1%** |
| unstripped, 15 sigs | 813 | 620 / 621 (99.8%) | 596 | **96.0%** |
| stripped, 1 sig | 412 | 227 / 621 (36.6%) | 218 | **96.0%** |
| stripped, 15 sigs | 412 | 227 / 621 (36.6%) | 218 | **96.0%** |

The last column is flat at 96% in every condition. **Given a function, the applier matches it.**
Applying fifteen signatures is not lossier than applying one. What goes wrong is the first
column: on the stripped input radare2 creates 412 functions where there are 755, and finds 227
of the 621 that have a pattern. The patterns are there, the bytes are there, `zfs` is never
asked.

It is a default, not a limitation. `aaa` finds 489 of 755, and `aaaa` and `aaa; aap` both find
750.

## Results

Three applications per binary: the harness default, the harness plus radare2's prelude scan, and
radare2 seeded with the `.eh_frame` function starts (`af @ <addr>` per FDE). Seeding uses no
ground truth, because `.eh_frame` is in the stripped file. It is the like-for-like column.

| crate | LTO | n_lib | sigs | `aaa` | `aaa; aap` | **FDE-seeded** | gain | rustsig-std |
|---|---|---|---|---|---|---|---|---|
| bat | Y | 4309 | 50 | 9.75% | 13.74% | **18.6%** | 1.90x | 28.6% |
| fd | Y | 3364 | 28 | 7.07% | 8.89% | **16.9%** | 2.39x | 24.6% |
| hexyl | Y | 1000 | 13 | 10.40% | 13.00% | **25.6%** | 2.46x | 57.3% |
| hyperfine | Y | 1171 | 27 | 10.25% | 12.64% | **24.7%** | 2.41x | 58.2% |
| just | Y | 2797 | 42 | 7.76% | 9.47% | **15.2%** | 1.95x | 45.0% |
| pastel | Y | 751 | 13 | 13.32% | 15.58% | **22.5%** | 1.69x | 68.7% |
| sd | Y | 1808 | 20 | 9.02% | 10.95% | **17.6%** | 1.96x | 47.4% |
| tokei | Y | 3308 | 43 | 6.80% | 15.69% | **36.1%** | 5.31x | 19.9% |
| zoxide | Y | 1017 | 12 | 9.83% | 12.09% | **27.3%** | 2.78x | 62.9% |
| dust | n | 1999 | 30 | 8.55% | 10.56% | **17.5%** | 2.05x | 54.4% |
| grex | n | 2565 | 21 | 35.59% | 52.48% | **86.2%** | 2.42x | 54.3% |
| ripgrep | n | 3993 | 22 | 26.50% | 40.45% | **70.7%** | 2.67x | 47.7% |
| xsv | n | 2052 | 28 | 36.70% | 52.83% | **71.8%** | 1.96x | 44.5% |

Median FLIRT library recall: **24.7%**. Median rustsig-std: **47.7%**. Median per-binary ratio
**2.24x**, rustsig winning 9 of 13. **FLIRT wins grex, xsv, ripgrep and tokei**. That is the
whole no-LTO stratum except dust, plus one binary from inside the LTO stratum.

## By bytes, not by functions

`aaa` misses are dominated by small leaf functions. On zoxide, the 100 functions matched under
`aaa` have median size 146 bytes, and the 180 additionally recovered by FDE-seeding have median
size **14**. Re-scoring by library bytes covered:

| crate | LTO | by count: `aaa` → seeded | by **bytes**: `aaa` → seeded |
|---|---|---|---|
| bat | Y | 9.7% → 18.6% (1.90x) | 8.2% → 9.6% (1.18x) |
| fd | Y | 7.1% → 16.9% (2.39x) | 4.1% → 6.1% (1.49x) |
| hexyl | Y | 10.4% → 25.6% (2.46x) | 6.2% → 7.4% (1.20x) |
| hyperfine | Y | 10.2% → 24.7% (2.41x) | 9.0% → 11.5% (1.27x) |
| just | Y | 7.8% → 15.2% (1.95x) | 4.4% → 6.0% (1.36x) |
| pastel | Y | 13.3% → 22.5% (1.69x) | 6.3% → 7.3% (1.16x) |
| sd | Y | 9.0% → 17.6% (1.96x) | 6.2% → 8.3% (1.33x) |
| tokei | Y | 6.8% → 36.1% (5.31x) | 5.1% → 18.7% (3.70x) |
| zoxide | Y | 9.8% → 27.3% (2.78x) | 10.6% → 12.3% (1.16x) |
| dust | n | 8.6% → 17.5% (2.05x) | 6.2% → 8.4% (1.34x) |
| grex | n | 35.6% → 86.2% (2.42x) | 41.8% → 75.6% (1.81x) |
| ripgrep | n | 26.5% → 70.7% (2.67x) | 31.0% → 63.7% (2.05x) |
| xsv | n | 36.7% → 71.8% (1.96x) | 38.9% → 58.9% (1.51x) |

Median by bytes: **9.6%** over all 13, **8.3%** on the LTO stratum. On most LTO binaries the
correction is almost entirely tiny functions, at a median byte-gain of 1.27x against a count-gain
of 2.39x. FLIRT therefore covers under a tenth of library *code volume* there, however it is
scored.
tokei is the exception inside the stratum, at 3.70x.

## LTO

| stratum | n | FLIRT (seeded) | rustsig-std |
|---|---|---|---|
| LTO | 9 | 22.5% | 47.4% |
| no-LTO | 4 | 71.3% | 51.0% |
| **degradation under LTO** | | **3.2x** | **1.08x** |

The mechanism is not a discovery artifact: `aaa`'s discovery ceiling is *better* on the LTO side
(61.3% vs 52.8%), so the stratification is not the harness. And a uniformly under-applying
harness preserves a ratio. That is exactly why the corrected numbers reproduce the 3.2x almost
exactly, and why the agreement confirms the caution rather than the harness.

RIFT recompiles the crate from source. A fresh build cannot reproduce the link-time inlining and
cross-crate decisions the target's LTO made, so the bytes diverge and the patterns miss. An
indexed donor binary was itself produced by a real link with real LTO.

That statement needs one qualification, which is in [`limits.md`](limits.md): a fresh build
reproduces LTO decisions perfectly well *if it uses the same LTO setting*. What it cannot
reproduce is an unknown configuration, and LTO is one coordinate of six.

## Precision

Zero FLIRT hits landed on author-labelled functions in any configuration, including FDE-seeded.
FLIRT essentially cannot false-positive, and near-exact byte matching means that holds
regardless of what corpus the signatures came from. This is a real advantage and it does not
degrade.

rustsig's naming precision on the same corpus is 97% to 99.7% (median 98.9%). One outlier, `sd`
at 90.9%, is undiagnosed rather than averaged away.

## What could not be tested, and one correction

IDA's own applier could not be tested. IDA Free 9.3 ships no IDAPython plugin and rejects the
`-S` batch switch, so RIFT's intended path cannot be driven headlessly. FDE-seeding is the
closest proxy, and a fair one. IDA's ELF loader parses `.eh_frame` and creates functions from
FDEs, which is precisely the universe the seeded run gets. Whether IDA then matches at the same rate as `zfs` is inference
from the positive control, not measurement.

A cross-check against RIFT's published numbers cannot be run. There are none. Checked:
upstream `microsoft/RIFT` (`git grep` over all `*.md`, no benchmark), the `version_1_stable`
RECON 2025 branch (walkthroughs, no counts), the Microsoft Security Blog (one illustrative
figure, no recall number), secondary press (qualitative). A ">90% of library functions labeled"
line surfaces in search-engine summaries but is not in either source when fetched directly.

One number we cited as external corroboration was ours. An earlier draft said RIFT's LTO
degradation "reproduces the 4.3x its own study found." That 4.3x traces to a local
`bench/STANDUP.md`, which is the same radare2 harness measured twice. It is a self-citation and
should not be read as validation by anyone.

## Reproduce

```sh
# signatures, per binary, with RIFT itself
PYTHONPATH=.rift-work/pydeps python3 rift_cli.py -f <crate>.stripped -c rift_config.linux.cfg -o <sigdir>

# three applications + scoring
python3 bench/scripts/round42_three_configs.py <crate>

# the rustsig column
python3 bench/scripts/bench_rustsig.py && python3 bench/scripts/paired_table.py
```

Per-binary output for all three configurations and both metrics is in
`bench/results/*.threeconfig.json`; the rustsig column is `bench/results/paired.json`.
Regenerated signature sets are not checked in (29 MB across the 13).

## Caveats

1. The corrected column re-derives FLIRT only. The rustsig column is unmodified.
2. FDE-seeding is an upper bound on *discovery*, not on FLIRT: it reaches 93% to 97% of the FDE
   universe, so the corrected figures are still slightly low.
3. The IDA path remains untested.
4. `aap` is not free. A prelude scan can create functions where there are none. It produced no
   author-side false positives here; that was not stress-tested beyond this corpus.
5. n=13, one corpus, one architecture, one ruler. Nothing is extrapolated.
