#!/bin/sh
# Full verification of the mbedtlspp working tree.
#
#   sh verify.sh
#
# Builds every target, runs the mbedtls self tests, then exercises both
# cpp-httplib backends (native mbedTLS and the OpenSSL compatibility bridge)
# as a TLS server and as a TLS client.

REPO="${MBEDTLSPP_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
T="${TEMP:-/tmp}"
cd "$REPO" || exit 1
fail=0

note() { echo; echo "===== $* ====="; }

BI="$REPO/include/mbedtls_build_info.hpp"
MAJOR=$(grep -m1 "define MBEDTLS_VERSION_MAJOR" "$BI" | awk '{print $3}')
VERSION=$(grep -m1 "define MBEDTLS_VERSION_STRING " "$BI" | tr -d '"' | awk '{print $3}')
echo "mbedtls $VERSION (major $MAJOR)"

TOOLS="$REPO/tools"
VCVARS="${MBEDTLSPP_VCVARS:-C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat}"
REPO_W=$(cygpath -w "$REPO")
TOOLS_W=$(cygpath -w "$TOOLS")

cat > "$T/verify_build.bat" <<BAT
@echo off
call "$VCVARS" >nul 2>&1
cd /d $REPO_W
if not exist build mkdir build
for %%T in (chk st httpsd native sample cliO cliM) do if not exist build\\%%T mkdir build\\%%T
cl /nologo /std:c++20 /EHsc /MD /c mbedtlspp_check.cpp /I. /Iinclude /Fo:build\\chk\\
echo RC_check=%ERRORLEVEL%
cl /nologo /std:c++20 /EHsc /MD $TOOLS_W\\selftest_main.cpp /I. /Iinclude /Fo:build\\st\\ /Fe:build\\selftest.exe /link ws2_32.lib advapi32.lib crypt32.lib
echo RC_selftest=%ERRORLEVEL%
cl /nologo /std:c++20 /EHsc /MD mbedtlspp_sample.cpp /I. /Iinclude /Fo:build\\sample\\ /Fe:build\\sample.exe /link ws2_32.lib advapi32.lib crypt32.lib
echo RC_sample=%ERRORLEVEL%
cl /nologo /std:c++20 /EHsc /MD mbedtlspp_sample_httpsd.cpp /I. /Iinclude /Fo:build\\httpsd\\ /Fe:build\\httpsd.exe /link ws2_32.lib advapi32.lib crypt32.lib
echo RC_httpsd=%ERRORLEVEL%
cl /nologo /std:c++20 /EHsc /MD mbedtlspp_sample_mbedtls.cpp /I. /Iinclude /Fo:build\\native\\ /Fe:build\\native.exe /link ws2_32.lib advapi32.lib crypt32.lib
echo RC_native=%ERRORLEVEL%
cl /nologo /std:c++20 /EHsc /MD /DCPPHTTPLIB_OPENSSL_SUPPORT=1 $TOOLS_W\\client_main.cpp /I. /Iinclude /Fo:build\\cliO\\ /Fe:build\\cli_openssl.exe /link ws2_32.lib advapi32.lib crypt32.lib
echo RC_cli_openssl=%ERRORLEVEL%
cl /nologo /std:c++20 /EHsc /MD /DCPPHTTPLIB_MBEDTLS_SUPPORT=1 $TOOLS_W\\client_main.cpp /I. /Iinclude /Fo:build\\cliM\\ /Fe:build\\cli_mbedtls.exe /link ws2_32.lib advapi32.lib crypt32.lib
echo RC_cli_mbedtls=%ERRORLEVEL%
BAT

note "build"
cmd //c "$(cygpath -w "$T/verify_build.bat")" > "$T/verify_build.log" 2>&1
grep -E "error C[0-9]|error LNK|RC_" "$T/verify_build.log"
for rc in $(grep -oE "RC_[a-z_]+=[0-9]+" "$T/verify_build.log"); do
  case "$rc" in *=0) ;; *) echo "BUILD FAILED: $rc"; fail=1 ;; esac
done

note "mbedtls self tests"
./build/selftest.exe | tail -3 || fail=1
./build/selftest.exe >/dev/null || fail=1

kill_srv() {
  netstat -ano 2>/dev/null | grep "0.0.0.0:8080" | awk '{print $NF}' | sort -u |
    while read -r p; do taskkill //F //PID "$p" >/dev/null 2>&1; done
  sleep 1
}

req() { printf 'GET /hi HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'; }

test_server() {
  exe="$1"; label="$2"
  kill_srv
  "./$exe" > "$T/verify_$label.log" 2>&1 &
  srv=$!
  sleep 3
  if [ "$(netstat -ano 2>/dev/null | grep -c '0.0.0.0:8080')" -eq 0 ]; then
    echo "$label: SERVER DID NOT START"; fail=1; return
  fi
  for cs in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_CCM_SHA256; do
    if req | openssl s_client -connect 127.0.0.1:8080 -tls1_3 -ciphersuites $cs -quiet -verify_quiet 2>/dev/null | grep -q "Hello World!"
      then echo "  ok   $label tls1.3 $cs"
      else echo "  FAIL $label tls1.3 $cs"; fail=1; fi
  done
  # mbedtls 4.x removed the static-RSA key exchange, so the non-ECDHE suites
  # only exist on 3.x.
  suites="ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384"
  suites="$suites ECDHE-RSA-CHACHA20-POLY1305 ECDHE-RSA-AES128-SHA256 ECDHE-RSA-AES256-SHA384"
  if [ "${MAJOR:-3}" -lt 4 ]; then
    suites="$suites AES128-GCM-SHA256 AES256-GCM-SHA384"
  fi
  for c in $suites; do
    if req | openssl s_client -connect 127.0.0.1:8080 -tls1_2 -cipher $c -quiet -verify_quiet 2>/dev/null | grep -q "Hello World!"
      then echo "  ok   $label tls1.2 $c"
      else echo "  FAIL $label tls1.2 $c"; fail=1; fi
  done
  body=$(curl -s -k --max-time 15 https://localhost:8080/hi)
  if [ "$body" = "Hello World!" ]; then echo "  ok   $label curl/schannel"
  else echo "  FAIL $label curl/schannel"; fail=1; fi
  for proto in tls1_2 tls1_3; do
    pids=''
    i=0
    while [ $i -lt 24 ]; do
      ( req | openssl s_client -connect 127.0.0.1:8080 -$proto -quiet -verify_quiet 2>/dev/null |
        grep -c "Hello World!" > "$T/vc$i.txt" ) &
      pids="$pids $!"
      i=$((i + 1))
    done
    for p in $pids; do wait "$p"; done
    ok=0; i=0
    while [ $i -lt 24 ]; do ok=$((ok + $(cat "$T/vc$i.txt"))); i=$((i + 1)); done
    if [ "$ok" -eq 24 ]; then echo "  ok   $label concurrency $proto 24/24"
    else echo "  FAIL $label concurrency $proto $ok/24"; fail=1; fi
  done
  kill_srv
}

note "server: OpenSSL compatibility bridge"
test_server build/httpsd.exe openssl_bridge
note "server: native mbedTLS"
test_server build/native.exe native_mbedtls

note "client"
CA="${MBEDTLSPP_CA_BUNDLE:-$T/ca-bundle.crt}"
if [ ! -f "$CA" ]; then
  for c in /usr/ssl/certs/ca-bundle.crt /mingw64/etc/ssl/certs/ca-bundle.crt \
           /etc/ssl/certs/ca-certificates.crt; do
    [ -f "$c" ] && cp "$c" "$CA" && break
  done
fi
[ -f "$CA" ] || { echo "no CA bundle found; set MBEDTLSPP_CA_BUNDLE"; fail=1; }
./build/cli_openssl.exe "$CA" || fail=1
./build/cli_mbedtls.exe "$CA" || fail=1
./build/cli_openssl.exe "$CA" | grep -q '\*\*\*' && { echo "client bridge: BAD accept"; fail=1; }
./build/cli_mbedtls.exe "$CA" | grep -q '\*\*\*' && { echo "client native: BAD accept"; fail=1; }

echo
if [ "$fail" -eq 0 ]; then echo "===== ALL CHECKS PASSED ====="; else echo "===== FAILURES PRESENT ====="; fi
exit $fail
