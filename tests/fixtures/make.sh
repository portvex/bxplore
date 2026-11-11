#!/bin/sh
# Regenerates the signature fixtures with OpenSSL, using throwaway keys that
# are deleted afterwards. Run from this directory: ./make.sh
# The .der files are what the tests read; nothing here is a real identity.
# The "cffx" in the names is the project's former name. It is baked into the
# committed .der files and asserted in tests/signatures.rs, so leave it.
set -e
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf 'The quick brown fox jumps over the lazy dog.\n' > message.txt

ca() { # name keyspec digest
    openssl req -x509 -newkey "$2" -nodes -keyout "$work/$1-ca.key" -out "$work/$1-ca.pem" -days 36500 -"$3" \
        -subj "/CN=cffx test root $1" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
}
leaf() { # name keyspec digest extensions
    openssl req -newkey "$2" -nodes -keyout "$work/$1.key" -out "$work/$1.csr" -subj "/CN=cffx test signer $1" 2>/dev/null
    printf '%s\n' "$4" > "$work/$1.ext"
    openssl x509 -req -in "$work/$1.csr" -CA "$work/$1-ca.pem" -CAkey "$work/$1-ca.key" -CAcreateserial -out "$work/$1.pem" \
        -days 36500 -"$3" -extfile "$work/$1.ext" 2>/dev/null
}
sign() { # name digest
    openssl cms -sign -binary -nodetach -outform DER -md "$2" -signer "$work/$1.pem" -inkey "$work/$1.key" \
        -certfile "$work/$1-ca.pem" -in message.txt -out "cms_$1.der"
}

ca rsa rsa:2048 sha256
leaf rsa rsa:2048 sha256 "keyUsage=digitalSignature"
sign rsa sha256

openssl ecparam -name prime256v1 -out "$work/p256.param"
ca p256 "ec:$work/p256.param" sha256
leaf p256 "ec:$work/p256.param" sha256 "keyUsage=digitalSignature"
sign p256 sha256

openssl ecparam -name secp384r1 -out "$work/p384.param"
ca p384 "ec:$work/p384.param" sha384
leaf p384 "ec:$work/p384.param" sha384 "keyUsage=digitalSignature"
sign p384 sha384

# A signer whose certificate was issued by an end entity certificate: the
# chain's signatures are all good, but "cffx test signer rogue" is not a CA.
ca rogue rsa:2048 sha256
leaf rogue rsa:2048 sha256 "keyUsage=digitalSignature"
openssl req -newkey rsa:2048 -nodes -keyout "$work/forged.key" -out "$work/forged.csr" -subj "/CN=cffx test forged signer" 2>/dev/null
openssl x509 -req -in "$work/forged.csr" -CA "$work/rogue.pem" -CAkey "$work/rogue.key" -CAcreateserial -out "$work/forged.pem" \
    -days 36500 -sha256 -extfile "$work/rogue.ext" 2>/dev/null
cat "$work/rogue.pem" "$work/rogue-ca.pem" > "$work/rogue-chain.pem"
openssl cms -sign -binary -nodetach -outform DER -md sha256 -signer "$work/forged.pem" -inkey "$work/forged.key" \
    -certfile "$work/rogue-chain.pem" -in message.txt -out cms_leaf_issued.der

# RFC 3161 timestamp token over message.txt, issued by a throwaway TSA.
ca tsa rsa:2048 sha256
leaf tsa rsa:2048 sha256 "extendedKeyUsage=critical,timeStamping"
cat > "$work/tsa.cnf" <<CNF
[tsa]
default_tsa = tsa_config
[tsa_config]
serial = $work/tsa.serial
crypto_device = builtin
signer_cert = $work/tsa.pem
certs = $work/tsa-ca.pem
signer_key = $work/tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ess_cert_id_chain = no
CNF
echo 01 > "$work/tsa.serial"
openssl ts -query -data message.txt -sha256 -cert -out "$work/query.tsq"
openssl ts -reply -config "$work/tsa.cnf" -section tsa_config -queryfile "$work/query.tsq" -token_out -out timestamp_token.der
ls -l ./*.der
