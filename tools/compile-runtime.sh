#!/bin/sh
set -eu
ROOT=$(pwd)
mkdir -p "$ROOT/.build" "$ROOT/runtime/amd64/licenses" "$ROOT/runtime/amd64/source"
cd "$ROOT/.build"
curl --fail --location --retry 3 --proto '=https' --tlsv1.2 https://download.strongswan.org/strongswan-6.1.0.tar.gz -o strongswan-6.1.0.tar.gz
printf '%s\n' 'd9484eea319481bda86f992fa69cbdbdd9c0d6f8b9a4bd793a7df45c0760d963  strongswan-6.1.0.tar.gz' | sha256sum -c -
tar xzf strongswan-6.1.0.tar.gz
cd strongswan-6.1.0
python3 "$ROOT/tools/disable-udp-gro.py" .
./configure --prefix=/synovpn --with-piddir=/var/packages/SynoVPN/var/run \
    --disable-defaults --disable-shared --enable-static --enable-monolithic \
    --enable-charon --enable-ikev2 --enable-kernel-netlink --enable-socket-default \
    --enable-vici --enable-openssl --enable-aes --enable-sha1 --enable-sha2 \
    --enable-hmac --enable-random --enable-nonce --enable-x509 --enable-revocation \
    --enable-constraints --enable-pubkey --enable-pkcs1 --enable-pkcs8 --enable-pem --enable-drbg
make -j2 LDFLAGS='-all-static'
make install
file /synovpn/libexec/ipsec/charon
# Static PIE is also valid; inspect ELF rather than matching file's wording.
python3 - <<'PY'
import pathlib, struct
p=pathlib.Path('/synovpn/libexec/ipsec/charon')
b=p.read_bytes()
assert b[:5]==b'\x7fELF\x02', 'charon must be ELF64'
offset=struct.unpack_from('<Q',b,32)[0]
size,count=struct.unpack_from('<HH',b,54)
assert all(struct.unpack_from('<I',b,offset+i*size)[0]!=3 for i in range(count)), 'charon has a dynamic interpreter'
PY
cp /synovpn/libexec/ipsec/charon "$ROOT/runtime/amd64/charon"
cp COPYING LICENSE "$ROOT/runtime/amd64/licenses/"
cp "$ROOT/.build/strongswan-6.1.0.tar.gz" "$ROOT/runtime/amd64/source/"
cp "$ROOT/tools/disable-udp-gro.py" "$ROOT/runtime/amd64/source/"
if [ -d /usr/share/licenses ]; then cp -r /usr/share/licenses/. "$ROOT/runtime/amd64/licenses/alpine-build-dependencies"; fi
