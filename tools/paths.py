"""Where everything lives. Override with environment variables if needed.

    MBEDTLSPP_REPO      this repository            (default: the parent of tools/)
    MBEDTLSPP_UPSTREAM  where the upstream clones sit
                        (default: the directory containing this repository)
    MBEDTLSPP_VCVARS    Visual Studio's vcvars64.bat

The two upstream clones are expected as <MBEDTLSPP_UPSTREAM>/mbedtls_up and
<MBEDTLSPP_UPSTREAM>/tfpsa_up:

    git clone --filter=blob:none --no-checkout https://github.com/Mbed-TLS/mbedtls.git mbedtls_up
    git clone --filter=blob:none --no-checkout https://github.com/Mbed-TLS/TF-PSA-Crypto.git tfpsa_up
"""
import os

_HERE = os.path.dirname(os.path.abspath(__file__)).replace('\\', '/')

REPO = os.environ.get('MBEDTLSPP_REPO', os.path.dirname(_HERE)).replace('\\', '/')
INC = REPO + '/include'

UPSTREAM = os.environ.get('MBEDTLSPP_UPSTREAM',
                          os.path.dirname(REPO)).replace('\\', '/')
MBEDTLS = UPSTREAM + '/mbedtls_up'
TFPSA = UPSTREAM + '/tfpsa_up'

VCVARS = os.environ.get(
    'MBEDTLSPP_VCVARS',
    r'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat')
