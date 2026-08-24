# Moving mbedtlspp to a new upstream mbedtls release

This is the working note for whoever does the next version bump. Everything
described here lives in `tools/`.

## What this port actually is

A mechanical rewrite of the mbedtls sources into one C++ translation unit:

| upstream | here |
| --- | --- |
| `library/aes.c` | `include/aes.cpp` |
| `library/common.h` | `include/common.hpp` |
| `include/mbedtls/aes.h` | `include/mbedtls_aes.hpp` |
| `include/mbedtls/private/aes.h` | `include/mbedtls_private_aes.hpp` |
| `include/psa/crypto.h` | `include/psa_crypto.hpp` |
| `include/tf-psa-crypto/version.h` | `include/tf-psa-crypto_version.hpp` |

One rule covers all of it: **flatten the path a file is included by**, replacing
`/` with `_` and `.h`/`.c` with `.hpp`/`.cpp`. A header under an `include/`
directory is included by its path below that directory; anything else is
included by bare name from its own directory. `tools/srcmap.py` derives the
whole mapping from the upstream tree that way, so a directory reshuffle upstream
(and 4.1 did reshuffle) needs no change here.

On top of the renaming:

* every file-scope `static` becomes `static inline`, and every public definition
  gets a `static inline` prefix, so the single translation unit has no duplicate
  symbols and unused code is discarded;
* `extern "C"` wrappers are commented out;
* `#include` targets are rewritten to the flattened names;
* file-local symbols that collide across files get a numeric suffix
  (`local_err_translation_7`, `K_2`, `test_data_2`, ...).

`mbedtlspp.hpp` includes every `.cpp` in dependency order. The order is **not**
alphabetical and it matters.

## The one thing that is not mechanical

`include/threading_alt.hpp` is written by hand, and `include/threading.cpp` has
a hand-written auto-registration block at the end. Keep both.

mbedtls clears its contexts with `memset` / `mbedtls_platform_zeroize()`, so a
`std::mutex` stored by value inside one gets destroyed under the library's feet:
the next lock touches a wrecked object, and the C++ destructor later runs over
zeroized memory. So the platform mutex type holds **only a pointer**; the real
`std::mutex` lives on the heap. Zeroizing then merely nulls the pointer, which
every entry point tolerates. The same applies to the condition variable that
mbedtls 4.x added.

The auto-registration exists because an application that forgets
`mbedtls_threading_set_alt()` gets a library with uninitialised mutexes and
crashes far from the cause.

## Doing a bump

Two upstream clones are expected next to this repository (override with
`MBEDTLSPP_UPSTREAM`); see `tools/paths.py`.

    git clone --filter=blob:none --no-checkout https://github.com/Mbed-TLS/mbedtls.git mbedtls_up
    git clone --filter=blob:none --no-checkout https://github.com/Mbed-TLS/TF-PSA-Crypto.git tfpsa_up

Then, from `tools/`:

    python bump2.py v4.2.0 v4.3.0            # dry run: what would change
    python bump2.py v4.2.0 v4.3.0 --apply    # do it
    # resolve the conflicts it lists (see below)
    python gen_upstream.py v4.3.0            # regenerate the generated sources
    python regen.py v4.3.0                   # mbedtlspp.hpp + forwarding headers
    python fix_includes.py                   # repair same-directory includes
    python autofix.py                        # compile, apply C -> C++ fixes, repeat
    sh verify.sh                             # build and test everything

Then commit, tag `vX.Y.Z`, push, and create the GitHub release.

### bump2.py

A three-way merge per file:

    base   = transform(upstream file at the old release)
    theirs = transform(upstream file at the new release)
    ours   = the file currently in include/

`transform` only approximates the original rewrite, but it is applied to both
`base` and `theirs`, so a systematic deviation cancels out and merges cleanly.
What is left as a conflict is a place where upstream touched a line the rewrite
also touched, or one of the hand-written fixes.

Files are keyed on the **port** name, so a header that merely moved upstream is
still recognised as the same file. Renames that basename matching cannot see go
in `EXTRA_RENAMES`.

**Resolving conflicts:** taking the upstream side is right almost every time —
the port's own edits are re-derived afterwards by `autofix.py` (casts, dedup
renames) or are in files upstream never touches. The exceptions to look at by
hand are `threading.cpp`, `threading_alt.hpp` and anything where "ours" holds a
deliberate fix. When in doubt, take upstream and let `verify.sh` catch it.

### gen_upstream.py

mbedtls does not ship some sources; its build system generates them. A
header-only library has no build system, so they are generated once and
committed:

| file | generator |
| --- | --- |
| `psa_crypto_driver_wrappers.hpp`, `..._no_static.cpp` | TF-PSA-Crypto `scripts/generate_driver_wrappers.py` |
| `tf_psa_crypto_config_check_*.hpp` | TF-PSA-Crypto `scripts/generate_config_checks.py` |
| `mbedtls_config_check_*.hpp` | mbedtls `scripts/generate_config_checks.py` |
| `ssl_debug_helpers_generated.cpp` | mbedtls `framework/scripts/generate_ssl_debug_helpers.py` |
| `error.cpp` | mbedtls `scripts/generate_errors.pl` |

Needs `pip install jinja2 jsonschema` and perl (Git for Windows has one). The
script checks out each repository's `framework` submodule at the pinned
revision and junctions `tfpsa_up` into `mbedtls_up/tf-psa-crypto`, because the
mbedtls generators read the crypto repository through that path.

For 3.x releases these files are in the source tree and the script does nothing.

### autofix.py

Compiles `mbedtlspp_check.cpp` and repairs, from the compiler's own
diagnostics, the four things that are legal C and not legal C++:

* **C2440** implicit `void *` to `T *` — inserts the cast the port uses elsewhere.
* **C2362** `goto` jumping over an initialised local — splits `T x = e;` into
  `T x; x = e;`. Everything in mbedtls is POD so this is always safe; a `const`
  scalar loses its `const`, which nothing relies on.
* **C2664** an argument C converts implicitly (`void *` to a typed parameter, an
  int to an enum) — casts that argument.
* **C2084 / C2371 / C2374** a file-local function, type or object whose name
  collides with another file's — renames it with the next free numeric suffix.

Fixes are applied bottom-up per file, because a fix can shift the line numbers
the compiler reported for everything below it.

Anything else is printed and left for a human.

### regen.py

Rewrites the `#include` list in `mbedtlspp.hpp` and regenerates the `mbedtls/`,
`psa/` and `tf-psa-crypto/` forwarding-header trees.

The include order is preserved: files that are gone are dropped, new ones are
appended. **Appending is a guess** — if a new source defines something an
earlier one uses, move it up by hand. That happened in 4.1 with
`psa_util_internal.cpp`, which defines the `psa_to_*_errors` tables that
`md.cpp`, `lms.cpp` and `pk*.cpp` use.

`EXCLUDE` lists sources that must never be amalgamated. mbedtls 4.x validates
the build configuration in translation units of their own
(`mbedtls_config.cpp`, `tf_psa_crypto_config.cpp`); the first thing they do is
`#undef` every configuration macro so a generated header can detect which ones
the user set. Harmless in a file that contains nothing else, fatal in a single
translation unit. Neither defines any code.

### verify.sh

Builds every target, runs the mbedtls self tests, then exercises both
cpp-httplib backends as a TLS server (TLS 1.3 and TLS 1.2 cipher suites,
Windows Schannel via curl, 24 concurrent requests) and as a TLS client against
real sites, including checking that a mismatched host and an expired
certificate are rejected.

It reads the version from `include/mbedtls_build_info.hpp` and skips the
static-RSA cipher suites on 4.x, where upstream removed them.

## Gotchas

* **Line endings.** Files in `include/` are a mix of CRLF and LF, and a few have
  mixed endings within one file. The tools preserve each file's dominant style;
  `sed -i` under MSYS does not, and turns a two-line change into a whole-file
  diff. Use python with `newline=''` or `git diff --ignore-cr-at-eol` to check.
* **BOM.** MSVC needs a UTF-8 BOM to read non-ASCII source correctly under a
  Japanese locale; several files have one and it must survive edits. Files with
  Japanese comments but no BOM produce `warning C4819`.
* **`mbedtlspp_check.cpp` has no `main()`** — it is a compile-only check. Build
  it with `/c`.
* **Config options move between files.** `MBEDTLS_THREADING_C` /
  `MBEDTLS_THREADING_ALT` are set by this port; in 3.x that was
  `mbedtls_mbedtls_config.hpp`, in 4.x it is `psa_crypto_config.hpp`. After a
  bump, check they are still set.
* **perl's `glob` chokes on a Windows drive letter**, so `generate_errors.pl`
  must be given relative paths. If `error.cpp` comes out at a few KB instead of
  ~23 KB, that is what happened.
* Optional drivers (`drivers/everest/`, `drivers/p256-m/`, `drivers/pqcp/`) are
  deliberately not ported; see `SKIP_PREFIXES` in `srcmap.py`.

## Known gaps

* `mbedtls_ssl_export_keying_material()` and the TLS 1.2/1.3 keying-material
  export helpers are not in the port. They were already missing in 3.6.4, so
  this is inherited rather than introduced; nothing in the amalgamation calls
  them, and `static inline` declarations that are never used are legal.
* Only MSVC is exercised by `verify.sh`. The mingw / clang / gcc command lines
  in README are inherited from earlier releases and are not part of the
  automated check.
