#!/usr/bin/env bash
set -euo pipefail

# Generate local test fixtures for AIA Chaser:
# - Root CA
# - Intermediate CA (DER & PEM)
# - Leaf certificate containing AIA caIssuers URI pointing to local MockAiaServer (http://127.0.0.1:8088/intermediate.der)

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"
mkdir -p "$DIR"

echo "Generating certificates in $DIR..."

# 1. Root CA
openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
  -keyout "$DIR/root_key.pem" \
  -out "$DIR/root.pem" \
  -subj "/CN=AIA Chaser Test Root CA/O=AiaChaser/C=US"

# 2. Intermediate CA
openssl req -newkey rsa:2048 -nodes \
  -keyout "$DIR/intermediate_key.pem" \
  -out "$DIR/intermediate.csr" \
  -subj "/CN=AIA Chaser Test Intermediate CA/O=AiaChaser/C=US"

cat <<EOF > "$DIR/intermediate.ext"
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

openssl x509 -req -in "$DIR/intermediate.csr" \
  -CA "$DIR/root.pem" \
  -CAkey "$DIR/root_key.pem" \
  -CAcreateserial \
  -out "$DIR/intermediate.pem" \
  -days 1825 \
  -extfile "$DIR/intermediate.ext"

# Convert intermediate to DER format for AIA distribution
openssl x509 -in "$DIR/intermediate.pem" -outform DER -out "$DIR/intermediate.der"

# 3. Leaf Certificate with AIA extension
openssl req -newkey rsa:2048 -nodes \
  -keyout "$DIR/leaf_key.pem" \
  -out "$DIR/leaf.csr" \
  -subj "/CN=localhost/O=AiaChaser Test/C=US"

cat <<EOF > "$DIR/leaf.ext"
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
authorityInfoAccess = caIssuers;URI:http://127.0.0.1:8088/intermediate.der

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in "$DIR/leaf.csr" \
  -CA "$DIR/intermediate.pem" \
  -CAkey "$DIR/intermediate_key.pem" \
  -CAcreateserial \
  -out "$DIR/leaf.pem" \
  -days 365 \
  -extfile "$DIR/leaf.ext"

echo "Certificates successfully generated in $DIR!"
