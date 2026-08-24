"""Produce the sources upstream generates at build time, and install them.

    python gen_upstream.py <release>

mbedtls does not ship these in the source tree; its build system runs a script
to make them. A header-only amalgamation has no build system, so they are
generated once here and vendored into include/.

    psa_crypto_driver_wrappers.h        TF-PSA-Crypto scripts/generate_driver_wrappers.py
    psa_crypto_driver_wrappers_no_static.c        (same script)
    tf_psa_crypto_config_check_{before,final,user}.h
                                        TF-PSA-Crypto scripts/generate_config_checks.py
    mbedtls_config_check_{before,final,user}.h
                                        mbedtls scripts/generate_config_checks.py
    ssl_debug_helpers_generated.c       mbedtls framework/scripts/generate_ssl_debug_helpers.py
    error.c                             mbedtls scripts/generate_errors.pl

Both repositories need their `framework` submodule checked out at the revision
the release pins; check_frameworks() reports if it is missing or stale.
For 3.x, error.c and ssl_debug_helpers_generated.c and the driver wrappers are
shipped in the source tree and nothing here is needed.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import srcmap
from portlib import write, transform

from paths import INC, MBEDTLS, TFPSA


def run(cwd, *cmd):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        print('FAILED in %s: %s' % (cwd, ' '.join(cmd)))
        print(r.stdout[-2000:])
        print(r.stderr[-2000:])
        raise SystemExit(1)
    return r.stdout


def framework_rev(root, rev):
    out = subprocess.run(['git', '-C', root, 'ls-tree', rev, 'framework'],
                         capture_output=True, text=True).stdout.split()
    return out[2] if len(out) >= 3 else None


def ensure_framework(root, rev, url='https://github.com/Mbed-TLS/mbedtls-framework.git'):
    want = framework_rev(root, rev)
    if not want:
        return
    fw = os.path.join(root, 'framework')
    if not os.path.isdir(os.path.join(fw, '.git')):
        run(root, 'git', 'clone', '-q', url, 'framework')
    have = subprocess.run(['git', '-C', fw, 'rev-parse', 'HEAD'],
                          capture_output=True, text=True).stdout.strip()
    if have != want:
        run(fw, 'git', 'fetch', '-q', 'origin')
        run(fw, 'git', 'checkout', '-q', want)
    print('framework in %-28s %s' % (os.path.basename(root), want[:12]))


def install(src, name, known):
    text = open(src, 'rb').read().decode('utf-8', 'surrogateescape')
    write(INC + '/' + name, transform(text, known))
    print('  installed %-44s %d bytes' % (name, os.path.getsize(INC + '/' + name)))


def main():
    release = sys.argv[1]
    if not release.startswith('v4'):
        print('%s ships these files in the source tree; nothing to generate.' % release)
        return 0

    trev = srcmap.submodule_rev(release)
    run(MBEDTLS, 'git', 'checkout', '-q', release)
    run(TFPSA, 'git', 'checkout', '-q', trev)
    ensure_framework(MBEDTLS, release)
    ensure_framework(TFPSA, trev)

    # mbedtls' own generators read the crypto repository through the submodule
    # path, so it has to be reachable there. A junction to the separate clone
    # is enough and always reflects the revision checked out above.
    link = os.path.join(MBEDTLS, 'tf-psa-crypto')
    if not os.path.isdir(link):
        subprocess.run(['cmd', '/c', 'mklink', '/J', link, TFPSA.replace('/', '\\')],
                       capture_output=True)
        print('linked %s -> %s' % (link, TFPSA))

    mgen = os.path.join(MBEDTLS, 'gen_out')
    tgen = os.path.join(TFPSA, 'gen_out')
    os.makedirs(mgen, exist_ok=True)
    os.makedirs(tgen, exist_ok=True)

    print('generating...')
    run(TFPSA, sys.executable, 'scripts/generate_driver_wrappers.py', 'gen_out')
    run(TFPSA, sys.executable, 'scripts/generate_config_checks.py', 'gen_out')
    run(MBEDTLS, sys.executable, 'scripts/generate_config_checks.py', 'gen_out')
    run(MBEDTLS, sys.executable, 'framework/scripts/generate_ssl_debug_helpers.py', 'gen_out')
    # Paths must stay relative: perl's glob does not cope with a Windows drive
    # letter, and silently matches nothing, which yields an error.c with only a
    # handful of codes in it.
    run(MBEDTLS, 'perl', 'scripts/generate_errors.pl',
        'tf-psa-crypto/drivers/builtin/include/mbedtls',
        'include/mbedtls',
        'scripts/data_files',
        'gen_out/error.c')

    files = [
        (tgen + '/psa_crypto_driver_wrappers.h', 'psa_crypto_driver_wrappers.hpp'),
        (tgen + '/psa_crypto_driver_wrappers_no_static.c', 'psa_crypto_driver_wrappers_no_static.cpp'),
        (tgen + '/tf_psa_crypto_config_check_before.h', 'tf_psa_crypto_config_check_before.hpp'),
        (tgen + '/tf_psa_crypto_config_check_final.h', 'tf_psa_crypto_config_check_final.hpp'),
        (tgen + '/tf_psa_crypto_config_check_user.h', 'tf_psa_crypto_config_check_user.hpp'),
        (mgen + '/mbedtls_config_check_before.h', 'mbedtls_config_check_before.hpp'),
        (mgen + '/mbedtls_config_check_final.h', 'mbedtls_config_check_final.hpp'),
        (mgen + '/mbedtls_config_check_user.h', 'mbedtls_config_check_user.hpp'),
        (mgen + '/ssl_debug_helpers_generated.c', 'ssl_debug_helpers_generated.cpp'),
        (mgen + '/error.c', 'error.cpp'),
    ]
    known = set(srcmap.source_map(release)) | {n for _s, n in files}
    for src, name in files:
        if not os.path.exists(src):
            print('  MISSING  %s (generator did not produce it)' % src)
            continue
        install(src, name, known)
    return 0


if __name__ == '__main__':
    sys.exit(main())
