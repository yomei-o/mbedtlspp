"""Port mbedtlspp from one upstream mbedtls release to another.

    python bump2.py <old-release> <new-release> [--apply]

Works across the 3.x -> 4.x split, where the crypto half moves into the
TF-PSA-Crypto repository and many headers move under `mbedtls/private/`.
Everything is keyed on the *port* file name (see srcmap.py), so a header that
merely moved upstream is still recognised as the same file and keeps its
history and any hand written fix in it.

Per file the update is a three-way merge:

    base   = transform(upstream file at <old-release>)
    theirs = transform(upstream file at <new-release>)
    ours   = mbedtlspp/include/<port name>

`transform` only approximates the original header-only rewrite, but it is
applied to both sides, so a systematic deviation cancels out and merges
cleanly. What is left as a conflict is where upstream touched a line the
rewrite also touched, or one of this repository's hand written fixes.
"""
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import srcmap
from portlib import INC, read, write, eol_of, to_lf, to_eol, transform

OLD, NEW = sys.argv[1], sys.argv[2]
APPLY = '--apply' in sys.argv

# Files that are part of the port itself, not of any upstream release.
HAND_WRITTEN = {'threading_alt.hpp', 'ssl_tls13_keys_orig.hpp'}

# Renames that basename matching cannot see.
EXTRA_RENAMES = {
    ('v3.6.7', 'v4.0.0'): {
        'common.hpp': 'tf_psa_crypto_common.hpp',
    },
}

CONFLICT = re.compile(
    r'<<<<<<< [^\n]*\n(.*?)\|\|\|\|\|\|\| [^\n]*\n(.*?)=======\n(.*?)>>>>>>> [^\n]*\n',
    re.S)


def show(entry):
    root, rev, path = entry
    r = subprocess.run(['git', '-C', root, 'show', rev + ':' + path],
                       capture_output=True)
    if r.returncode != 0:
        return None
    return r.stdout.decode('utf-8', 'surrogateescape')


def merge3(ours, base, theirs):
    d = tempfile.mkdtemp()
    po, pb, pt = d + '/ours', d + '/base', d + '/theirs'
    for p, s in ((po, ours), (pb, base), (pt, theirs)):
        write(p, s)
    r = subprocess.run(['git', 'merge-file', '-p', '--diff3', po, pb, pt],
                       capture_output=True)
    return r.stdout.decode('utf-8', 'surrogateescape')


def auto_resolve(txt):
    resolved = [0]
    remaining = [0]

    def sub(m):
        if m.group(1) == m.group(2):
            resolved[0] += 1
            return m.group(3)
        remaining[0] += 1
        return m.group(0)

    return CONFLICT.sub(sub, txt), resolved[0], remaining[0]


def detect_renames(old_map, new_map):
    base = lambda p: p.rsplit('/', 1)[-1]
    rem = set(old_map) - set(new_map)
    add = set(new_map) - set(old_map)
    by_old, by_new = {}, {}
    for n in rem:
        by_old.setdefault(base(old_map[n][2]), []).append(n)
    for n in add:
        by_new.setdefault(base(new_map[n][2]), []).append(n)
    ren = {}
    for bn, olds in by_old.items():
        news = by_new.get(bn)
        if news and len(olds) == 1 and len(news) == 1:
            ren[olds[0]] = news[0]
    ren.update(EXTRA_RENAMES.get((OLD, NEW), {}))
    return ren


old_map = srcmap.source_map(OLD)
new_map = srcmap.source_map(NEW)
renames = detect_renames(old_map, new_map)
known = set(old_map) | set(new_map)

added, removed, renamed, merged, conflicted = [], [], [], [], []

for name, entry in sorted(new_map.items()):
    dst = INC + '/' + name
    theirs = show(entry)
    if theirs is None:
        continue

    src_name = name
    if name not in old_map:
        prev = [o for o, n in renames.items() if n == name]
        src_name = prev[0] if prev else None

    if src_name is None or src_name not in old_map:
        added.append(name)
        if APPLY:
            write(dst, transform(theirs, known))
        continue

    src_path = INC + '/' + src_name
    if not os.path.exists(src_path):
        added.append(name)
        if APPLY:
            write(dst, transform(theirs, known))
        continue

    base = show(old_map[src_name])
    style = eol_of(src_path)
    out = merge3(to_lf(read(src_path)),
                 transform(base, known),
                 transform(theirs, known))
    out, res, rem = auto_resolve(out)
    if rem:
        conflicted.append((name, rem, res))
    else:
        merged.append(name)
    if APPLY:
        write(dst, to_eol(out, style))
        if src_name != name:
            os.remove(src_path)
    if src_name != name:
        renamed.append((src_name, name))

for name in sorted(set(old_map) - set(new_map)):
    if name in renames or name in HAND_WRITTEN:
        continue
    removed.append(name)
    p = INC + '/' + name
    if APPLY and os.path.exists(p):
        os.remove(p)

print('== %s -> %s%s ==' % (OLD, NEW, '  (APPLIED)' if APPLY else '  (dry run)'))
print('merged  : %d' % len(merged))
print('renamed : %d' % len(renamed))
print('added   : %d  %s' % (len(added), ' '.join(added)))
print('removed : %d  %s' % (len(removed), ' '.join(removed)))
print('FILES NEEDING MANUAL RESOLUTION: %d' % len(conflicted))
for name, rem, res in conflicted:
    print('   %-44s %d unresolved, %d auto' % (name, rem, res))
