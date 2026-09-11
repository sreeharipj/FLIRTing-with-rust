# rustsig

Names library functions in a stripped x86-64 Rust ELF by relocation-aware body hash, against a
database built from already-linked donor binaries. No recompilation, no crate detection, no
network.

How it works and how the numbers were measured: [`../docs/method.md`](../docs/method.md).

## Install

```sh
pip install capstone pyelftools
cargo install rustfilt      # must be on PATH
```

## Usage

```sh
# build a database from unstripped donor binaries
python3 rustsig.py build db.json.gz bat.debug ripgrep.debug fd.debug ...

# label a stripped target
python3 rustsig.py label db.json.gz target.stripped
python3 rustsig.py label db.json.gz target.stripped --json | jq .
python3 rustsig.py label db.json.gz target.stripped --min-confidence-frac 0.10
```

`build` takes *unstripped* binaries: donors, not the target. It needs `nm` symbols. `label` takes
the stripped binary you are trying to read.

`build` parallelises across donors with a 4-worker cap. That cap is deliberate. Some real debug
binaries run 300 to 500 MB, and each worker holds one. At 8 and 16 wide the run died silently on
a 14 GB machine. A 100-donor pool takes minutes.

Databases are written as `.json.gz` by extension and read by gzip magic byte, so a renamed or
redistributed database still loads.

## `--min-confidence-frac`

A signature must have been independently observed in at least this fraction of the donor pool
before it is trusted. Default 0.08, so a 110-donor database requires 9 independent confirmations.

| `--min-confidence-frac` | median naming precision | floor (worst of 5 targets) | median library recall |
|---|---|---|---|
| 0.03 | 98.6% | 97.8% | 14.7% |
| 0.05 | 98.8% | 98.4% | 12.7% |
| 0.08 (default) | 99.1% | 98.7% | 12.0% |
| 0.10 | 99.2% | 98.7% | 11.6% |
| 0.15 | 99.2% | 98.7% | 9.9% |

Measured on cross-corpus targets at a 110-donor pool. The same table at 32 donors reads 87.5%
median and 85.2% floor at 0.08.

It is a fraction rather than an absolute count because an absolute threshold needs re-tuning
every time the pool grows. Precision drifts *down* at fixed N, because new donors stack
lower-quality matches under an unchanged bar. `--min-confidence N` overrides with an absolute
count. `N=1` is the max-recall "is this library code at all" mode, for elimination rather than
naming.

## Building a donor corpus

More donors improves coverage, precision at a given confidence fraction, and the precision floor,
and saturates at about 8 to 13 donors for a target unlike the pool.

`../bench/scripts/grow_corpus.sh` builds a donor set with `cargo install` and debug info forced on
(`CARGO_PROFILE_RELEASE_DEBUG=true CARGO_PROFILE_RELEASE_STRIP=false`, since most published crates
strip release builds). Adapt the crate list to your target's domain. Keep the `.debug` copy for
`build`.

The database behind the numbers in this repo was built from 110 real-world crates (CLI, TUI and
async/network tools) and is about 9 MB. It is not checked in.

## Output

`label --json` emits one record per matched function:

| field | meaning |
|---|---|
| `addr`, `size`, `n_insns` | function bounds from `.eh_frame`, and its instruction count |
| `name` | a representative demangled instantiation, for readability |
| `identity` | the generic-erased identity actually matched on |
| `confidence` | number of distinct donor binaries that produced this body hash |

`name` is display-only. Nothing matches on it, and its type parameters come from whichever donor
supplied the shortest name, so `<anyhow::Error>::construct::<ini::Error>` on a target that does
not link `ini` means `anyhow::Error::construct`, not a mislabel.

Table mode is for a human skimming a triage pass; JSON is for feeding another tool. Nothing here
parses its own table output, so the two are free to diverge.

## `triage.py`

Composes rustsig with [unhusk](https://github.com/sreeharipj/unhusk), which finds *author* code
from `core::panic::Location` metadata at high precision and low recall.

```sh
python3 triage.py target.stripped --rustsig-db db.json.gz
python3 triage.py target.stripped --rustsig-db db.json.gz --crate mycrate --json
```

Buckets every function as `AUTHOR`, `LIBRARY` or `UNKNOWN`, and reports how much of the binary
that leaves to read. On a `strip --strip-all`ed ripgrep with a database built from 9 other
binaries: 4,932 functions to read instead of 8,790, retaining 91.6% of author code.

Needs `unhusk` built and on `PATH`, or passed with `--unhusk-bin`. `--crate` passes through to
unhusk's own `--crate`.

## Tests

```sh
python3 test_erase_generics.py   # identity normalisation, no corpus needed
./test_smoke.sh                  # 3-donor DB, held-out target, ~seconds
```

`test_smoke.sh` asserts that the confidence filter actually filters, that a gzipped database
loads, and that `triage.py` returns both buckets non-empty. It skips cleanly when no corpus is
present. It is a "did I just break the tool" gate, not an evaluation.
