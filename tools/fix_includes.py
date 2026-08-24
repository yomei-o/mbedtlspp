"""Repair include directives that the flattening rewrote to a name that does not exist.

    python fix_includes.py

Upstream files include their neighbours by bare name (`#include "crypto_driver_common.h"`
from inside include/psa/), but in the flat port that header is called
`psa_crypto_driver_common.hpp`. Flattening the include path alone cannot know
that, so this pass fixes up any `#include "X.hpp"` where X.hpp is missing and
exactly one file in include/ is named `<prefix>_X.hpp`.

`*_alt.hpp` targets are left alone: those are user supplied hooks that only
exist when the corresponding MBEDTLS_*_ALT option is enabled.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paths import INC
INCRE = re.compile(r'^(\s*#\s*include\s+")([^"]+\.hpp)(".*)$')


def main():
    have = set(os.listdir(INC))
    fixed = 0
    unresolved = {}
    for f in sorted(have):
        if not (f.endswith('.cpp') or f.endswith('.hpp')):
            continue
        p = INC + '/' + f
        raw = open(p, 'rb').read().decode('utf-8', 'surrogateescape')
        crlf = raw.count('\r\n') * 2 > raw.count('\n')
        lines = raw.replace('\r\n', '\n').split('\n')
        changed = False
        for i, ln in enumerate(lines):
            m = INCRE.match(ln)
            if not m:
                continue
            target = m.group(2)
            if target in have or target.endswith('_alt.hpp'):
                continue
            cands = [k for k in have if k.endswith('_' + target)]
            if len(cands) == 1:
                lines[i] = m.group(1) + cands[0] + m.group(3)
                changed = True
                fixed += 1
            else:
                unresolved.setdefault(target, []).append(f)
        if changed:
            s = '\n'.join(lines)
            if crlf:
                s = s.replace('\n', '\r\n')
            open(p, 'wb').write(s.encode('utf-8', 'surrogateescape'))
    print('rewritten includes:', fixed)
    if unresolved:
        print('UNRESOLVED (%d):' % len(unresolved))
        for t, fs in sorted(unresolved.items()):
            print('   %-40s from %s' % (t, ', '.join(sorted(set(fs))[:4])))
    return 0


if __name__ == '__main__':
    sys.exit(main())
