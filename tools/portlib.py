"""Shared helpers for porting an upstream mbedtls tree onto the mbedtlspp layout."""
import os, re, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paths import MBEDTLS as UP, REPO, INC


def up_paths(root=UP):
    """Every upstream source file we care about -> its port file name."""
    m = {}
    for f in sorted(os.listdir(root + '/library')):
        if f.endswith('.c'):
            m['library/' + f] = f[:-2] + '.cpp'
        elif f.endswith('.h'):
            m['library/' + f] = f[:-2] + '.hpp'
    for sub, pre in (('mbedtls', 'mbedtls_'), ('psa', 'psa_')):
        d = root + '/include/' + sub
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if f.endswith('.h'):
                m['include/' + sub + '/' + f] = pre + f[:-2] + '.hpp'
    return m


def read(p):
    return open(p, 'rb').read().decode('utf-8', 'surrogateescape')


def write(p, s):
    open(p, 'wb').write(s.encode('utf-8', 'surrogateescape'))


def eol_of(p):
    if not os.path.exists(p):
        return 'lf'
    b = open(p, 'rb').read()
    return 'crlf' if b.count(b'\r\n') * 2 > b.count(b'\n') else 'lf'


def to_lf(s):
    return s.replace('\r\n', '\n')


def to_eol(s, style):
    s = s.replace('\r\n', '\n')
    return s.replace('\n', '\r\n') if style == 'crlf' else s


# ---------------------------------------------------------------- transform

INCRE = re.compile(r'^(\s*#\s*include\s+)([<"])([^>"]+)([>"])(.*)$')


def _inc_target(name, known, quoted):
    """Rewrite an include target the way the port does, or None to leave it."""
    if not name.endswith('.h'):
        return None
    if quoted:
        # mbedtls only quote-includes its own headers, and the port rewrites
        # them all -- including the *_alt.h hooks that have no upstream file.
        return name[:-2].replace('/', '_') + '.hpp'
    cand = name[:-2].replace('/', '_') + '.hpp'
    return cand if cand in known else None


_DEF = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*[A-Za-z0-9_ 	\*]*[ 	\*]([A-Za-z_][A-Za-z0-9_]*)\s*\(')
_KEY = ('static', 'inline', 'extern', 'typedef', 'return', 'if', 'while', 'for',
        'switch', 'case', 'else', 'do', 'sizeof', 'struct ', 'union ', 'enum ',
        'const struct', 'MBEDTLS_MAYBE_UNUSED', '#')


def _is_public_def(ln):
    """True for a top-level definition that the port prefixes with static inline."""
    if not ln or ln[0] in ' 	#/*}){':
        return False
    if ln.startswith(_KEY):
        return False
    if '=' in ln.split('(')[0]:
        return False
    return bool(_DEF.match(ln))


def _comment_extern_c(lines):
    """Comment out the `extern "C"` wrappers, as the port does.

    Everything ends up in one C++ translation unit, so the wrappers would give
    the functions C linkage and clash with `static inline`. The port keeps them
    visible but disabled rather than deleting them.
    """
    out = list(lines)
    i = 0
    while i < len(out):
        if out[i].strip() == '#ifdef __cplusplus':
            j = i + 1
            while j < len(out) and not out[j].strip():
                j += 1
            if j < len(out) and out[j].strip() in ('extern "C" {', '}'):
                k = j + 1
                while k < len(out) and not out[k].strip():
                    k += 1
                if k < len(out) and out[k].strip() == '#endif':
                    for x in (i, j, k):
                        out[x] = '// ' + out[x]
                    i = k + 1
                    continue
        i += 1
    return out


def transform(text, known):
    """Approximate the mbedtlspp source transformation.

    It does not have to match the original tool byte for byte: it is only used
    on the `theirs` side of a merge conflict, where the same approximation was
    applied to `base`, so any systematic deviation cancels out.
    """
    out = []
    in_error = False
    for ln in to_lf(text).split('\n'):
        # The original tool lower-cased the MBEDTLS_ prefix inside #error
        # messages. Harmless, but it has to be reproduced or every #error line
        # upstream touches turns into a conflict.
        if in_error or ln.lstrip().startswith('#error'):
            in_error = ln.rstrip().endswith('\\')
            out.append(ln.replace('MBEDTLS_', 'mbedtls_'))
            continue
        m = INCRE.match(ln)
        if m:
            t = _inc_target(m.group(3), known, m.group(2) == '"')
            if t:
                ln = m.group(1) + m.group(2) + t + m.group(4) + m.group(5)
            out.append(ln)
            continue
        mu = re.sub(r'^(\s*)MBEDTLS_MAYBE_UNUSED\s+static\s+',
                    r'\1static inline MBEDTLS_MAYBE_UNUSED ', ln)
        if mu != ln:
            out.append(mu)
            continue
        # Only file scope statics become `static inline`; a function local
        # static cannot be inline and the port leaves those alone.
        ln = re.sub(r'^static\s+inline\s+', 'static inline  ', ln)
        ln = re.sub(r'^static\s+(?!inline)', 'static inline  ', ln)
        if _is_public_def(ln):
            ln = 'static inline ' + ln
        out.append(ln)
    return '\n'.join(_comment_extern_c(out))


# ---------------------------------------------------------------- git access

def git_show(rev, path, root=UP):
    r = subprocess.run(['git', '-C', root, 'show', rev + ':' + path],
                       capture_output=True)
    if r.returncode != 0:
        return None
    return r.stdout.decode('utf-8', 'surrogateescape')


def changed_files(a, b, root=UP):
    r = subprocess.run(['git', '-C', root, 'diff', '--name-status', a, b,
                        '--', 'library', 'include'], capture_output=True, text=True)
    out = []
    for line in r.stdout.splitlines():
        parts = line.split('\t')
        out.append((parts[0][0], parts[-1]))
    return out


def up_paths_rev(rev, root=UP):
    """Same mapping as up_paths(), but for the tree at `rev`."""
    r = subprocess.run(['git', '-C', root, 'ls-tree', '-r', '--name-only', rev],
                       capture_output=True, text=True)
    m = {}
    for p in r.stdout.splitlines():
        if p.startswith('library/') and (p.endswith('.c') or p.endswith('.h')):
            f = p[len('library/'):]
            if '/' in f:
                continue
            m[p] = f[:-2] + ('.cpp' if p.endswith('.c') else '.hpp')
        elif p.startswith('include/mbedtls/') and p.endswith('.h'):
            m[p] = 'mbedtls_' + p[len('include/mbedtls/'):-2] + '.hpp'
        elif p.startswith('include/psa/') and p.endswith('.h'):
            m[p] = 'psa_' + p[len('include/psa/'):-2] + '.hpp'
    return m
