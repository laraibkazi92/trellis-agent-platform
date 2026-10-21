#!/bin/sh
# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0
#
# Generate an internal CA and a server certificate for the Trellis edge tunnel.
# The CA stays with the operator; edges only ever see ca.pem.
#
#   ./make-certs.sh --name trellis.internal --ip 10.0.0.41
#
# See docs/proxy-tls.md for the full runbook.

set -eu
umask 077

NAME=""
IP=""
OUT="./gateway/ssl"
DAYS=825
FORCE=0

usage() {
    cat <<'EOF'
Usage: make-certs.sh --name DNS | --ip ADDR [--out DIR] [--days N] [--force]

  --name   DNS name the edge dials (adds a DNS SAN)
  --ip     IPv4 address the edge dials (adds an IP SAN)
           Pass both when edges may dial either; at least one is required.
  --out    output directory (default: ./gateway/ssl)
  --days   server certificate lifetime in days (default: 825)
  --force  replace an existing ca.pem/ca.key/cert.pem/key.pem in --out

Writes ca.pem, ca.key, cert.pem, key.pem.

  central host : cert.pem + key.pem  -> /etc/nginx/ssl/ (or the terminator)
  every edge   : ca.pem             -> tls_ca_file

Keep ca.key offline. Replacing the CA means re-trusting it on every edge, so
renew the *server* certificate with the same CA whenever possible.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --name) NAME=${2:-}; shift 2 ;;
        --ip) IP=${2:-}; shift 2 ;;
        --out) OUT=${2:-}; shift 2 ;;
        --days) DAYS=${2:-}; shift 2 ;;
        --force) FORCE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[ -n "$NAME" ] || [ -n "$IP" ] || { echo "ERROR: pass --name and/or --ip" >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo "ERROR: openssl not found" >&2; exit 2; }
case "$DAYS" in
    ''|*[!0-9]*) echo "ERROR: --days must be a positive integer" >&2; exit 2 ;;
esac
[ "$DAYS" -gt 0 ] || { echo "ERROR: --days must be a positive integer" >&2; exit 2; }

# Build the SAN list from what the operator says the edge will dial. A cert that
# only has a CN verifies nowhere: the TLS stack checks the SAN and nothing else.
SAN=""
if [ -n "$NAME" ]; then
    SAN="DNS:$NAME"
fi
if [ -n "$IP" ]; then
    case "$IP" in
        *[!0-9.]*|.*|*.) echo "ERROR: --ip must be an IPv4 address (got '$IP')" >&2; exit 2 ;;
    esac
    if [ -n "$SAN" ]; then
        SAN="$SAN,IP:$IP"
    else
        SAN="IP:$IP"
    fi
fi

mkdir -p "$OUT"
if [ "$FORCE" -ne 1 ]; then
    for f in ca.pem ca.key cert.pem key.pem; do
        if [ -e "$OUT/$f" ]; then
            echo "ERROR: $OUT/$f already exists; pass --force to replace it" >&2
            exit 2
        fi
    done
fi

CN=${NAME:-$IP}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

# CA: long-lived, only signs server certs (no path below it).
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    -keyout "$TMP/ca.key" -out "$TMP/ca.pem" \
    -subj "/CN=Trellis Internal CA ($CN)" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1

openssl req -newkey rsa:2048 -sha256 -nodes \
    -keyout "$TMP/key.pem" -out "$TMP/server.csr" \
    -subj "/CN=$CN" >/dev/null 2>&1

cat > "$TMP/server.ext" <<EOF
subjectAltName=$SAN
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF

openssl x509 -req -in "$TMP/server.csr" -CA "$TMP/ca.pem" -CAkey "$TMP/ca.key" \
    -CAcreateserial -out "$TMP/cert.pem" -days "$DAYS" -sha256 \
    -extfile "$TMP/server.ext" >/dev/null 2>&1

cp "$TMP/ca.pem" "$OUT/ca.pem"
cp "$TMP/ca.key" "$OUT/ca.key"
cp "$TMP/cert.pem" "$OUT/cert.pem"
cp "$TMP/key.pem" "$OUT/key.pem"
chmod 600 "$OUT/ca.key" "$OUT/key.pem"
chmod 644 "$OUT/ca.pem" "$OUT/cert.pem"

# Fail here rather than on the edge: verify the leaf against the CA and print
# the SAN the edge will check.
openssl verify -CAfile "$OUT/ca.pem" "$OUT/cert.pem" >/dev/null
openssl x509 -in "$OUT/cert.pem" -noout -subject -ext subjectAltName -enddate

cat <<EOF

Wrote $OUT/{ca.pem,ca.key,cert.pem,key.pem}

Central host:
  cert.pem, key.pem  -> the TLS listener (nginx /etc/nginx/ssl, or deploy/tls/)
Every edge:
  ca.pem             -> tls_ca_file: /etc/trellis/tls/ca.pem

Keep ca.key offline; it is only needed to sign a renewed certificate.
EOF
