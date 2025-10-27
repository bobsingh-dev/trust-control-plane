#!/usr/bin/env sh
set -eu

OUT="/work/certs"
mkdir -p "$OUT"

# Short-lived certs to simulate rotation pressure
DAYS="${DAYS:-2}"

# 1) Local CA
if [ ! -f "$OUT/ca.key" ]; then
  openssl genrsa -out "$OUT/ca.key" 4096
fi
openssl req -x509 -new -nodes -key "$OUT/ca.key" -sha256 -days 3650 -subj "/CN=trust-local-CA" -out "$OUT/ca.crt"

# 2) ServiceA server cert with SPIFFE URI SAN
cat > "$OUT/serviceA.cnf" <<EOF
[req]
distinguished_name=req
req_extensions=req_ext
prompt=no
[req_ext]
subjectAltName=URI:spiffe://trust.local/serviceA,DNS:serviceA
EOF
openssl genrsa -out "$OUT/serviceA.key" 2048
openssl req -new -key "$OUT/serviceA.key" -subj "/CN=serviceA" -config "$OUT/serviceA.cnf" -out "$OUT/serviceA.csr"
openssl x509 -req -in "$OUT/serviceA.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial -out "$OUT/serviceA.crt" -days "$DAYS" -sha256 -extensions req_ext -extfile "$OUT/serviceA.cnf"

# 3) ServiceB client cert with SPIFFE URI SAN
cat > "$OUT/serviceB.cnf" <<EOF
[req]
distinguished_name=req
req_extensions=req_ext
prompt=no
[req_ext]
subjectAltName=URI:spiffe://trust.local/serviceB
EOF
openssl genrsa -out "$OUT/serviceB.key" 2048
openssl req -new -key "$OUT/serviceB.key" -subj "/CN=serviceB" -config "$OUT/serviceB.cnf" -out "$OUT/serviceB.csr"
openssl x509 -req -in "$OUT/serviceB.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial -out "$OUT/serviceB.crt" -days "$DAYS" -sha256 -extensions req_ext -extfile "$OUT/serviceB.cnf"

echo "✅ Certificates generated in $OUT"
