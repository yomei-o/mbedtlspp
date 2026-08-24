"""Map an upstream mbedtls release onto mbedtlspp's flat include/ directory.

mbedtls 3.x keeps everything in one repository. mbedtls 4.x splits the crypto
half out into TF-PSA-Crypto, so a 4.x release is a pair of revisions, and 4.1
reshuffled that repository again (platform/, extras/, utilities/, ...).

Rather than track those layouts by hand, the directory list is discovered from
the tree and the port file name follows one rule: flatten the path a file is
*included* by.

    library/aes.c                    -> aes.cpp
    library/common.h                 -> common.hpp
    include/mbedtls/aes.h            -> mbedtls_aes.hpp
    include/psa/crypto.h             -> psa_crypto.hpp
    include/mbedtls/private/aes.h    -> mbedtls_private_aes.hpp
    include/tf-psa-crypto/version.h  -> tf-psa-crypto_version.hpp
    platform/threading.c             -> threading.cpp

A header under an `include/` directory is included by its path below that
directory; everything else is included by bare name from its own directory.
portlib.transform rewrites `#include` directives by the same rule, so the two
always agree.
"""
import subprocess

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paths import MBEDTLS, TFPSA

# Not part of the library: tests, sample programs, build glue, and the optional
# alternative drivers the port does not enable.
SKIP_PREFIXES = (
    'tests/', 'programs/', 'framework/', 'scripts/', 'docs/', 'doxygen/',
    'cmake/', 'configs/', '3rdparty/', 'pkgconfig/',
    'drivers/everest/', 'drivers/pqcp/', 'drivers/p256-m/',
)


def submodule_rev(mbedtls_rev):
    """The TF-PSA-Crypto commit an mbedtls 4.x revision pins."""
    r = subprocess.run(['git', '-C', MBEDTLS, 'ls-tree', mbedtls_rev, 'tf-psa-crypto'],
                       capture_output=True, text=True)
    parts = r.stdout.split()
    return parts[2] if len(parts) >= 3 else None


def include_prefix(path):
    """How a file at `path` is spelled in an #include, minus the file name."""
    marker = '/include/'
    if path.startswith('include/'):
        rest = path[len('include/'):]
    elif marker in path:
        rest = path.split(marker, 1)[1]
    else:
        return ''
    return rest.rsplit('/', 1)[0] + '/' if '/' in rest else ''


def port_name(path):
    fname = path.rsplit('/', 1)[-1]
    ext = '.cpp' if fname.endswith('.c') else '.hpp'
    return (include_prefix(path) + fname[:-2]).replace('/', '_') + ext


def _tree(root, rev):
    r = subprocess.run(['git', '-C', root, 'ls-tree', '-r', '--name-only', rev],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit('cannot list %s at %s: %s' % (root, rev, r.stderr.strip()))
    return r.stdout.splitlines()


def _collect(out, root, rev):
    for path in _tree(root, rev):
        if not (path.endswith('.c') or path.endswith('.h')):
            continue
        if any(path.startswith(p) for p in SKIP_PREFIXES):
            continue
        name = port_name(path)
        if name in out and out[name][2] != path:
            raise SystemExit('port name collision: %s (%s vs %s)'
                             % (name, out[name][2], path))
        out[name] = (root, rev, path)


def source_map(release):
    """release tag -> {port file name: (repo root, revision, upstream path)}"""
    out = {}
    _collect(out, MBEDTLS, release)
    if release.startswith('v4'):
        trev = submodule_rev(release)
        if not trev:
            raise SystemExit('no tf-psa-crypto revision pinned by ' + release)
        _collect(out, TFPSA, trev)
    return out


if __name__ == '__main__':
    import sys
    rel = sys.argv[1]
    m = source_map(rel)
    print(rel, 'files:', len(m))
    for k in sorted(m)[:10]:
        print('  %-38s %s' % (k, m[k][2]))
