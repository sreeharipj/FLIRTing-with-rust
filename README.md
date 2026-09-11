# FLIRTing with Rust

**FLIRT names about a quarter of the library functions in a stripped Rust binary, and a tenth of
the library code. `rustsig`, in this repository, names 47.7% at 99.1% precision.**

| median of 13 real binaries | by function count | by code volume |
|---|---|---|
| FLIRT | 24.7% | 9.6% |
| FLIRT, LTO builds (n=9) | 22.5% | 8.3% |
| rustsig | **47.7%** | not scored |

Rust monomorphizes generics, and the linker optimises across crates. A signature built by
recompiling a crate is therefore not the code that shipped. rustsig hashes normalised function
bodies from donor binaries that are already linked, so each donor carries its build configuration
in its own bytes.

```sh
pip install capstone pyelftools && cargo install rustfilt
python3 rustsig/rustsig.py build db.json.gz bat.debug ripgrep.debug ...   # unstripped donors
python3 rustsig/rustsig.py label db.json.gz target.stripped              # stripped target
```

Docs: [benchmark](docs/benchmark.md), [method](docs/method.md), [inlining](docs/inlining.md),
[limits](docs/limits.md).

Small print: FLIRT here is signatures built by [RIFT](https://github.com/microsoft/RIFT), applied
with radare2's `zfs` seeded from `.eh_frame`, because RIFT's own path needs IDA Pro. A positive
control puts that applier at 96.0%, so it is not the limit. Prebuilt signature sets, such as
Oxidizer's, are not measured. rustsig is x86-64 ELF only, and its database is not in this
repository. MIT.
