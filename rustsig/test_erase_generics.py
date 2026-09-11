#!/usr/bin/env python3
"""Regression tests for erase_generics()'s bracket-depth counter.

Cross-validation against Ghidra's Function ID hash found that erase_generics treated any
'>' character as closing a generic bracket -- including the one in '->'.
A generic parameter that is itself a function-pointer type (`fn(&A,&B) ->
bool`, exactly what slice::sort_by/sort_unstable_by's comparator-closure
machinery instantiates on) leaked everything after the arrow:
erase_generics('foo::bar<T, fn(&A,&B) -> bool>') returned 'foo::barbool'
instead of 'foo::bar'. Two places had the same bug: the impl-wrapper-unwrap
pass's depth counter, and the main erasure pass's depth counter -- both
fixed by not decrementing depth on a '>' immediately preceded by '-'.

Run: python3 test_erase_generics.py
"""
from rustsig import erase_generics

CASES = [
    # (input, expected) -- the reported bug, minimal repro
    ('foo::bar<baz::Qux, fn(&A, &B) -> bool>', 'foo::bar'),
    # real instances from the donor corpus
    ('core::slice::sort::shared::pivot::median3_rec<'
     'regex_syntax::hir::literal::Literal, '
     'fn(&regex_syntax::hir::literal::Literal, '
     '&regex_syntax::hir::literal::Literal) -> bool>',
     'core::slice::sort::shared::pivot::median3_rec'),
    ('std::sys::fs::unix::stat::call<'
     'fn(&core::ffi::c_str::CStr) -> core::result::Result<'
     'std::sys::fs::unix::FileAttr, std::io::error::Error>, '
     '(&core::ffi::c_str::CStr)>',
     'std::sys::fs::unix::stat::call'),
    # arrow inside a nested generic, not just a top-level one
    ('a::b<c::d<fn() -> u8>>::e', 'a::b::e'),
    # multiple arrows in one generic parameter list
    ('f<fn(&A) -> bool, fn(&B) -> bool>::g', 'f::g'),
    # arrow-free cases must still work (no regression on the common path)
    ('Vec<u8>::push::h0123456789abcdef', 'Vec::push'),
    ('alloc::vec::Vec<u8, alloc::alloc::Global>::len', 'alloc::vec::Vec::len'),
    # a literal '->' at depth 0 (outside any generic) must be left alone
    ('a::b -> c::d', 'a::b->c::d'),
    # impl-wrapper unwrap pass (the other depth counter with the same bug)
    ('<impl core::fmt::Debug for pkg::Foo<fn(&A) -> bool>>::fmt', 'pkg::Foo::fmt'),
]


def main():
    failures = 0
    for inp, expected in CASES:
        got = erase_generics(inp)
        ok = got == expected
        status = 'ok' if ok else 'FAIL'
        print(f"[{status}] erase_generics({inp!r})\n         -> {got!r}" +
              ('' if ok else f"  (expected {expected!r})"))
        if not ok:
            failures += 1
    print(f"\n{len(CASES) - failures}/{len(CASES)} passed")
    if failures:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
