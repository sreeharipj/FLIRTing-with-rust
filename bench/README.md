# bench

Scripts and per-binary results behind [`../docs/benchmark.md`](../docs/benchmark.md).

The corpus itself is not checked in: 13 crates as `.stripped` + `.debug` twins, plus the
regenerated FLIRT signature sets (29 MB across the 13). Both are reproducible. The signatures
come from `rift_cli.py`, and the corpus from the build script the ruler's project ships.

Paths come from the environment so the scripts run outside the machine they were written on:

| variable | default | what it points at |
|---|---|---|
| `CORPUS_OUT` | `corpus/out` | `<crate>.stripped` and `<crate>.debug` pairs |
| `GT_DIR` | `../results/gt` | `<crate>.gt.tsv`, the DWARF ruler dumps |
| `RESULTS_DIR` | `../results` | where sweeps and caches are written |
| `RUSTSIG_DIR` | `../../rustsig` | so the scripts import the tool under test |
| `RIFT_BENCH_BIN`, `RIFT_BENCH_GT` | unset | RIFT's own held-out benchmark corpus |

## Scripts

| script | what it does |
|---|---|
| `bench_rustsig.py` | leave-one-out over the 13 binaries, both database configurations |
| `paired_table.py` | joins the rustsig and FLIRT columns into `results/paired.json` |
| `round42_three_configs.py` | applies each FLIRT signature set three ways (`aaa`, `aaa; aap`, and radare2 seeded from `.eh_frame` FDE starts) and scores all three |
| `evaluate.py` | coverage, naming precision and library recall against a ruler |
| `frac_confidence_exp.py` | the `--min-confidence-frac` threshold sweep |
| `build_index.py` | caches raw per-donor rows so a sweep costs minutes, not hours |
| `grow_corpus.sh` | builds a donor set with `cargo install`, debug info forced on |
| `extract_inline.py` | pulls `DW_TAG_inlined_subroutine` ranges and normalised hashes out of donor DWARF |
| `scan.py` | the blind sliding-window fragment scan |

## Results

`paired.json` holds the joined per-binary comparison.

`<crate>.threeconfig.json` holds, per binary, all three FLIRT applications scored by both
metrics (function count and library bytes), plus the matched FDE sets and the signature count
RIFT produced. These are the raw evidence for the harness correction in
[`../docs/benchmark.md`](../docs/benchmark.md).
