"""Apply the mechanical C -> C++ fixes that a freshly ported mbedtls needs.

    python autofix.py            # compile, fix, repeat until clean or stuck

mbedtls is C. Two constructs in it are not valid C++ and reappear at every
version bump, so they are fixed from the compiler's own diagnostics rather than
by hand:

  C2440  implicit `void *` -> `T *` (mbedtls_calloc / malloc results).
         Fixed by inserting the C style cast the port already uses elsewhere.

  C2362  `goto` jumping over a local that has an initialiser. Everything in
         mbedtls is POD, so splitting `T x = e;` into `T x; x = e;` is always
         safe and is the smallest change that satisfies C++.

Anything else is reported and left alone -- those need a human.
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paths import REPO, VCVARS

BAT = os.environ.get('TEMP', 'C:/temp') + '/autofix_build.bat'

BS = chr(92)
BUILD = '\n'.join([
    '@echo off',
    'call "%s" >nul 2>&1' % VCVARS,
    'cd /d %s' % REPO.replace('/', BS),
    'if not exist build mkdir build',
    'cl /nologo /std:c++20 /EHsc /MD /c mbedtlspp_check.cpp /I. /Iinclude'
    ' /Fo:build' + BS + 'autofix.obj',
    'echo EXITCODE=%ERRORLEVEL%',
    '',
])

ERR = re.compile(r'^(?P<file>[^(\n]+)\((?P<line>\d+)\)\s*:\s*error (?P<code>C\d+)\s*:\s*(?P<msg>.*)$')
QUOTED = re.compile(r"'([^']*)'")


def compile_once():
    open(BAT, 'w').write(BUILD)
    r = subprocess.run(['cmd', '/c', BAT], capture_output=True)
    txt = r.stdout.decode('cp932', 'replace') + r.stderr.decode('cp932', 'replace')
    errs = []
    for line in txt.splitlines():
        m = ERR.match(line.strip())
        if m:
            errs.append((m.group('file'), int(m.group('line')),
                         m.group('code'), m.group('msg')))
    ok = 'EXITCODE=0' in txt
    return ok, errs, txt


def read_lines(path):
    with open(path, 'rb') as f:
        raw = f.read()
    crlf = raw.count(b'\r\n') * 2 > raw.count(b'\n')
    return raw.decode('utf-8', 'surrogateescape').replace('\r\n', '\n').split('\n'), crlf


def write_lines(path, lines, crlf):
    s = '\n'.join(lines)
    if crlf:
        s = s.replace('\n', '\r\n')
    with open(path, 'wb') as f:
        f.write(s.encode('utf-8', 'surrogateescape'))


def abspath(f):
    f = f.replace('\\', '/')
    return f if os.path.isabs(f) else REPO + '/' + f


DECL = re.compile(r'^(?P<indent>\s*)(?P<type>.*?[\s\*])(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<init>.*)$')


def fix_c2362(path, lineno, msg):
    """Split `T x = expr;` into `T x; x = expr;` so goto may cross it."""
    names = QUOTED.findall(msg)
    if not names:
        return False
    name = names[0]
    lines, crlf = read_lines(path)
    i = lineno - 1
    if i >= len(lines):
        return False
    # the initialiser may span several lines; find where the statement ends
    j = i
    while j < len(lines) and ';' not in lines[j]:
        j += 1
    if j >= len(lines):
        return False
    stmt = '\n'.join(lines[i:j + 1])
    m = DECL.match(stmt.split('\n')[0])
    if not m or m.group('name') != name:
        return False
    indent, typ = m.group('indent'), m.group('type')
    if typ.lstrip().startswith('const ') and '*' not in typ:
        # a const object cannot be split, so drop the const: these are local
        # scalars in C code, nothing relies on their constness.
        typ = typ.lstrip()[len('const '):]
    head = indent + typ + name + ';'
    rest = indent + name + ' = ' + m.group('init')
    body = [head, rest] + lines[i + 1:j + 1]
    lines[i:j + 1] = body
    write_lines(path, lines, crlf)
    return True


CAST = re.compile(r'^(?P<head>.*?=\s*)(?P<rhs>\S.*)$')


def fix_c2440(path, lineno, msg):
    """Insert the C style cast the port uses for mbedtls_calloc / malloc."""
    q = QUOTED.findall(msg)
    # msg looks like:  '=': 'void *' -> 'mbedtls_mpi_uint *'
    target = None
    for t in q:
        if t not in ('=', 'void *', 'void*') and t.endswith('*'):
            target = t
    if not target:
        return False
    lines, crlf = read_lines(path)
    i = lineno - 1
    if i >= len(lines):
        return False
    m = CAST.match(lines[i])
    if not m or m.group('rhs').startswith('('):
        return False
    lines[i] = m.group('head') + '(' + target + ') ' + m.group('rhs')
    write_lines(path, lines, crlf)
    return True


def _call_extent(s, open_pos):
    """Index just past the ')' that closes the '(' at open_pos, or -1."""
    depth = 0
    for i in range(open_pos, len(s)):
        if s[i] in '([{':
            depth += 1
        elif s[i] in ')]}':
            depth -= 1
            if depth == 0:
                return i
    return -1


def _split_args(s):
    """Split an argument list (without the outer parentheses) at top-level commas."""
    out, depth, cur = [], 0, ''
    for ch in s:
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur)
            cur = ''
            continue
        cur += ch
    out.append(cur)
    return out


def fix_c2664(path, lineno, msg):
    """Cast a call argument that C converts implicitly and C++ does not.

    Covers `void *` results handed straight to a typed parameter and ints
    handed to an enum parameter -- both legal C, both rejected by C++.
    """
    q = QUOTED.findall(msg)
    if len(q) < 3:
        return False
    sig, dst = q[0], q[-1]
    between = msg.split("'" + sig + "'", 1)[-1]
    m = re.search(r'(\d+)', between)
    if not m:
        return False
    argno = int(m.group(1))
    fname = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(', sig)
    if not fname:
        return False
    fname = fname.group(1)
    lines, crlf = read_lines(path)
    i = lineno - 1
    if i >= len(lines):
        return False
    # a call may start on an earlier line than the one the argument is on
    for start in range(i, max(-1, i - 8), -1):
        pos = lines[start].find(fname + '(')
        if pos < 0:
            continue
        open_pos = pos + len(fname)
        block = '\n'.join(lines[start:min(len(lines), i + 8)])
        base = sum(len(lines[k]) + 1 for k in range(start, start)) + open_pos
        close = _call_extent(block, base)
        if close < 0:
            continue
        inner = block[base + 1:close]
        args = _split_args(inner)
        if len(args) < argno:
            continue
        target = args[argno - 1]
        if target.strip().startswith('(' + dst + ')'):
            return False
        lead = len(target) - len(target.lstrip())
        args[argno - 1] = target[:lead] + '(' + dst + ')' + target[lead:]
        new_block = block[:base + 1] + ','.join(args) + block[close:]
        end = min(len(lines), i + 8)
        lines[start:end] = new_block.split('\n')
        write_lines(path, lines, crlf)
        return True
    return False


IDENT = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(')


def fix_c2084(path, lineno, msg):
    """Rename a duplicate definition, the way the port de-duplicates symbols.

    Every mbedtls source ends up in one translation unit, so file local helpers
    that share a name (`local_err_translation`, round constant tables, ...)
    collide. The port renames the later one with a numeric suffix; do the same.
    """
    q = QUOTED.findall(msg)
    if not q:
        return False
    if '(' in q[0]:
        m = IDENT.search(q[0])
        if not m:
            return False
        name = m.group(1)
    else:
        name = q[0].strip()
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name):
        return False
    lines, crlf = read_lines(path)
    text = '\n'.join(lines)
    # The candidate has to be free across the whole amalgamation, not just in
    # this file, or the collision simply moves and the rename runs again.
    inc = os.path.dirname(path)
    taken = set()
    for f in os.listdir(inc):
        if f.endswith(('.cpp', '.hpp')):
            with open(os.path.join(inc, f), 'rb') as fh:
                blob = fh.read().decode('utf-8', 'surrogateescape')
            taken.update(re.findall(r'\b%s_\d+\b' % re.escape(name), blob))
    for n in range(2, 60):
        cand = '%s_%d' % (name, n)
        if cand not in taken:
            break
    else:
        return False
    new = re.sub(r'\b%s\b' % re.escape(name), cand, text)
    if new == text:
        return False
    write_lines(path, new.split('\n'), crlf)
    return True


# C2084 duplicate function body, C2371 duplicate type, C2374 duplicate object:
# all three are the same single-translation-unit name clash.
FIXERS = {'C2362': fix_c2362, 'C2440': fix_c2440, 'C2664': fix_c2664,
          'C2084': fix_c2084, 'C2371': fix_c2084, 'C2374': fix_c2084}


def main():
    for round_no in range(1, 41):
        ok, errs, txt = compile_once()
        if ok:
            print('round %d: compiles cleanly' % round_no)
            return 0
        if not errs:
            print('round %d: build failed with no parsable errors' % round_no)
            print(txt[-3000:])
            return 1
        applied = 0
        seen = set()
        # Bottom-up per file: a fix can add lines, which would invalidate the
        # line numbers the compiler reported for anything below it.
        for f, ln, code, msg in sorted(errs, key=lambda e: (e[0], -e[1])):
            key = (f, ln, code)
            if key in seen:
                continue
            seen.add(key)
            fn = FIXERS.get(code)
            if not fn:
                continue
            p = abspath(f)
            if not os.path.exists(p):
                continue
            try:
                if fn(p, ln, msg):
                    applied += 1
                    print('  %s:%s %s fixed' % (f, ln, code))
            except Exception as e:
                print('  %s:%s %s fixer failed: %s' % (f, ln, code, e))
        print('round %d: %d errors, %d fixed' % (round_no, len(errs), applied))
        if not applied:
            print('STUCK -- remaining errors need a human:')
            for f, ln, code, msg in errs[:25]:
                print('   %s(%s) %s: %s' % (f, ln, code, msg[:110]))
            return 1
    print('gave up after 40 rounds')
    return 1


if __name__ == '__main__':
    sys.exit(main())
