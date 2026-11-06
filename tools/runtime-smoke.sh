#!/bin/sh
set -eu
SMOKE_DIR=$(mktemp -d /tmp/synovpn-smoke.XXXXXX)
SMOKE_CHARON=${SYNOVPN_SMOKE_CHARON:-/out/charon}
SMOKE_PROBE=${SYNOVPN_SMOKE_PROBE:-/probe}
cat > "$SMOKE_DIR/strongswan.conf" <<EOF
charon {
 threads = 16
 load_modular = no
 load = random nonce openssl sha1 sha2 aes hmac x509 revocation constraints pubkey pkcs1 pkcs8 pem kernel-netlink socket-default vici
 filelog {
  stdout {
   default = 2
   flush_line = yes
  }
 }
 plugins {
  vici { socket = unix://$SMOKE_DIR/charon.vici }
 }
}
EOF
mkdir -p /var/packages/SynoVPN/var/run
STRONGSWAN_CONF="$SMOKE_DIR/strongswan.conf" "$SMOKE_CHARON" > "$SMOKE_DIR/charon.log" 2>&1 &
CHARON=$!
cleanup() { kill "$CHARON" 2>/dev/null || true; wait "$CHARON" 2>/dev/null || true; rm -f "$SMOKE_DIR/strongswan.conf" "$SMOKE_DIR/charon.log" "$SMOKE_DIR/charon.vici"; rmdir "$SMOKE_DIR" 2>/dev/null || true; }
trap cleanup EXIT
COUNT=0
while [ ! -S "$SMOKE_DIR/charon.vici" ]; do
  COUNT=$((COUNT + 1))
  if [ "$COUNT" -gt 50 ]; then cat "$SMOKE_DIR/charon.log"; exit 1; fi
  sleep 0.1
done
if ! SYNOVPN_TEST_VICI="$SMOKE_DIR/charon.vici" "$SMOKE_PROBE"; then cat "$SMOKE_DIR/charon.log"; exit 1; fi
