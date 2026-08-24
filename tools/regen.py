"""Regenerate the parts of mbedtlspp that are derived from the file list.

    python regen.py

  * mbedtlspp.hpp  -- the amalgamation includes every .cpp in include/.
  * mbedtls/, psa/, tf-psa-crypto/  -- one forwarding header per public header,
    so that cpp-httplib's native mbedTLS backend can `#include <mbedtls/ssl.h>`.

The amalgamation keeps its hand written prologue (everything up to the first
`#include "` of a ported file) and its epilogue; only the include list between
them is rewritten. threading.cpp stays first because it has to define the
mutex callbacks before anything pulls in a context type.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paths import REPO, INC

# Sources that must never be amalgamated. mbedtls 4.x validates the build
# configuration in translation units of their own; the first thing they do is
# `#undef` every configuration macro so that a generated header can detect
# which ones the user set. That is fine in a file that contains nothing else,
# and fatal in a single translation unit build. Neither file defines any code.
EXCLUDE = {'mbedtls_config.cpp', 'tf_psa_crypto_config.cpp'}


def amalgamation_sources(existing_order):
    """Keep the current order, drop what is gone, append what is new.

    The order is not alphabetical and it matters: a definition has to precede
    its use in a single translation unit, so e.g. cipher_wrap.cpp comes before
    cipher.cpp and threading.cpp comes first of all. Preserving the existing
    order keeps that hand tuning across version bumps.
    """
    have = {f for f in os.listdir(INC) if f.endswith('.cpp')} - EXCLUDE
    kept = [f for f in existing_order if f in have]
    added = sorted(have - set(kept))
    return kept + added


def regen_amalgamation():
    p = REPO + '/mbedtlspp.hpp'
    raw = open(p, 'rb').read().decode('utf-8', 'surrogateescape')
    crlf = raw.count('\r\n') * 2 > raw.count('\n')
    lines = raw.replace('\r\n', '\n').split('\n')

    inc = re.compile(r'^#include "([^"]+\.(?:cpp|hpp))"$')
    first = next(i for i, l in enumerate(lines) if inc.match(l))
    last = max(i for i, l in enumerate(lines) if inc.match(l))

    existing = [inc.match(l).group(1) for l in lines[first:last + 1] if inc.match(l)]
    body = ['#include "%s"' % f for f in amalgamation_sources(existing)]
    out = lines[:first] + body + lines[last + 1:]
    s = '\n'.join(out)
    if crlf:
        s = s.replace('\n', '\r\n')
    open(p, 'wb').write(s.encode('utf-8', 'surrogateescape'))
    print('mbedtlspp.hpp: %d sources' % len(body))


PUBLIC_DIRS = ('mbedtls', 'psa', 'tf-psa-crypto')


def public_headers(release):
    """<dir>/<relative path>.h that upstream exposes, from the real file map."""
    import srcmap
    out = []
    for name, (_root, _rev, path) in srcmap.source_map(release).items():
        if not name.endswith('.hpp'):
            continue
        for d in PUBLIC_DIRS:
            marker = '/' + d + '/'
            if marker in path:
                rel = path.split(marker, 1)[1]
                out.append((d, rel[:-2], name))
                break
    return out


def regen_forwarding(release):
    wanted = public_headers(release)
    have = set(os.listdir(INC))
    counts = {}
    for d, rel, src in wanted:
        if src not in have:
            continue
        path = REPO + '/' + d + '/' + rel + '.h'
        os.makedirs(os.path.dirname(path), exist_ok=True)
        body = ('// mbedtlspp forwarding header: <%s/%s.h> -> the header-only'
                ' amalgamation.\n#pragma once\n#include <mbedtlspp.hpp>\n'
                % (d, rel))
        open(path, 'wb').write(body.encode('utf-8'))
        counts[d] = counts.get(d, 0) + 1
    keep = {REPO + '/' + d + '/' + rel + '.h' for d, rel, src in wanted if src in have}
    removed = 0
    for d in PUBLIC_DIRS:
        root = REPO + '/' + d
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for f in files:
                p = os.path.join(dirpath, f).replace('\\', '/')
                if f.endswith('.h') and p not in keep:
                    os.remove(p)
                    removed += 1
        for dirpath, dnames, files in os.walk(root, topdown=False):
            if not os.listdir(dirpath):
                os.rmdir(dirpath)
    for d in PUBLIC_DIRS:
        if counts.get(d):
            print('%-16s %d forwarding headers' % (d + '/', counts[d]))
    print('pruned stale forwarding headers:', removed)


if __name__ == '__main__':
    release = sys.argv[1]
    regen_amalgamation()
    regen_forwarding(release)
