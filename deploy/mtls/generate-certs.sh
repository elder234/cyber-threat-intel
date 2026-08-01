#!/usr/bin/env bash
#
# Aegis CTI — private-CA mTLS bootstrap.
#
# Generates a self-owned root CA, a server certificate for the Caddy edge, and
# one or more client certificates. Nothing is ever published to Certificate
# Transparency logs, and the edge only completes a TLS handshake with a device
# holding a client cert issued by this CA — a port scanner or a password
# brute-forcer gets a TLS alert, never an HTTP response.
#
# Usage:
#   ./generate-certs.sh init [-i <ip> ...] [-d <hostname> ...] [--force]
#       Create the CA + server cert. Pass the address(es) you reach the
#       dashboard at, e.g.:  ./generate-certs.sh init -i 203.0.113.9
#       (defaults to localhost + 127.0.0.1).
#   ./generate-certs.sh client <name>
#       Issue one more client cert (one per device/user). The .p12 is
#       protected by $MTLS_CLIENT_P12_PASSWORD (>= 8 chars).
#
# On every device after that:
#   - trust deploy/mtls/certs/ca.crt as a root CA (removes the TLS warning),
#   - import the <name>.p12 into the browser / keychain (client identity),
#   - browse to https://<address>:8443.
#
# curl / API scripts:  curl --cacert deploy/mtls/certs/ca.crt \
#       --cert deploy/mtls/certs/<name>.crt --key deploy/mtls/certs/<name>.key \
#       https://<address>:8443/api/health
#
# Re-run `init` to rotate the SERVER cert (the CA is kept, so client certs stay
# valid). Re-run `init --force` to also rotate the CA — this invalidates every
# client cert, so re-issue them afterwards.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS="$DIR/certs"
DAYS_CA=3650
DAYS_LEAF=825
ORG="Aegis CTI"

mkdir -p "$CERTS"
need() { command -v "$1" >/dev/null 2>&1 || { echo "error: missing required tool: $1" >&2; exit 1; }; }
need openssl

gen_key() { openssl genrsa 4096 -out "$1" 2>/dev/null; }

[ $# -eq 0 ] && { sed -n '2,32p' "$0" | sed 's/^# \?//'; exit 1; }
cmd="$1"; shift

case "$cmd" in
  init)
    IPS=(); DNS=(); FORCE=0
    while [ $# -gt 0 ]; do
      case "$1" in
        -i) IPS+=("$2"); shift 2 ;;
        -d) DNS+=("$2"); shift 2 ;;
        --force) FORCE=1; shift ;;
        *) echo "error: unknown arg: $1" >&2; exit 1 ;;
      esac
    done
    if [ ${#IPS[@]} -eq 0 ] && [ ${#DNS[@]} -eq 0 ]; then
      IPS+=(127.0.0.1); DNS+=(localhost)
    fi

    CA_KEY="$CERTS/ca.key"; CA_CRT="$CERTS/ca.crt"
    HAVE_CA=0
    if [ -f "$CA_KEY" ] && [ -f "$CA_CRT" ]; then HAVE_CA=1; fi

    TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

    if [ "$HAVE_CA" -eq 0 ]; then
      echo "→ generating private root CA"
      gen_key "$TMP/ca.key"
      openssl req -x509 -new -key "$TMP/ca.key" -sha256 -days "$DAYS_CA" \
        -subj "/C=XX/O=$ORG/CN=Aegis CTI Private CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "$TMP/ca.crt"
      mv "$TMP/ca.key" "$CA_KEY"; mv "$TMP/ca.crt" "$CA_CRT"
    elif [ "$FORCE" -eq 1 ]; then
      echo "→ rotating CA (backing up old CA first — this invalidates ALL client certs)"
      mv "$CA_KEY" "$CA_KEY.old.$(date +%s)"
      mv "$CA_CRT" "$CA_CRT.old.$(date +%s)"
      gen_key "$TMP/ca.key"
      openssl req -x509 -new -key "$TMP/ca.key" -sha256 -days "$DAYS_CA" \
        -subj "/C=XX/O=$ORG/CN=Aegis CTI Private CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "$TMP/ca.crt"
      mv "$TMP/ca.key" "$CA_KEY"; mv "$TMP/ca.crt" "$CA_CRT"
    else
      echo "→ CA already exists; regenerating the server cert only (client certs stay valid)"
    fi

    SAN=""
    for ip in "${IPS[@]}"; do SAN="$SAN,IP:$ip"; done
    for d in "${DNS[@]}"; do SAN="$SAN,DNS:$d"; done
    SAN="${SAN#,}"

    echo "→ generating server cert (SAN: $SAN)"
    gen_key "$TMP/server.key"
    openssl req -new -key "$TMP/server.key" -sha256 -subj "/C=XX/O=$ORG/CN=aegis-edge" \
      -out "$TMP/server.csr"
    openssl x509 -req -in "$TMP/server.csr" -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
      -days "$DAYS_LEAF" -sha256 \
      -extfile <(printf "subjectAltName=%s\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE" "$SAN") \
      -out "$TMP/server.crt"
    mv "$TMP/server.key" "$CERTS/server.key"; mv "$TMP/server.crt" "$CERTS/server.crt"

    chmod 600 "$CERTS"/*.key 2>/dev/null || true
    echo "done. server cert updated — CA unchanged, so client certs stay valid — in: $CERTS/"
    if [ "$HAVE_CA" -eq 0 ]; then
      echo "next:  MTLS_CLIENT_P12_PASSWORD='<strong-password>' ./generate-certs.sh client <your-name>"
    fi
    echo "then:  docker compose restart caddy"
    ;;

  client)
    [ $# -eq 1 ] || { echo "usage: ./generate-certs.sh client <name>" >&2; exit 1; }
    NAME="$1"
    case "$NAME" in
      *[!a-zA-Z0-9._-]*) echo "error: name may only contain [a-zA-Z0-9._-]" >&2; exit 1 ;;
    esac
    [ -f "$CERTS/ca.crt" ] || { echo "error: run ./generate-certs.sh init first" >&2; exit 1; }
    P12_PASS="${MTLS_CLIENT_P12_PASSWORD:-}"
    if [ ${#P12_PASS} -lt 8 ]; then
      echo "error: set MTLS_CLIENT_P12_PASSWORD to at least 8 chars to protect $NAME.p12" >&2
      exit 1
    fi

    TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

    echo "→ issuing client cert: $NAME"
    gen_key "$TMP/client.key"
    openssl req -new -key "$TMP/client.key" -sha256 -subj "/C=XX/O=$ORG/CN=$NAME" \
      -out "$TMP/client.csr"
    openssl x509 -req -in "$TMP/client.csr" -CA "$CERTS/ca.crt" -CAkey "$CERTS/ca.key" -CAcreateserial \
      -days "$DAYS_LEAF" -sha256 \
      -extfile <(printf "keyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nbasicConstraints=critical,CA:FALSE") \
      -out "$TMP/client.crt"
    openssl pkcs12 -export -inkey "$TMP/client.key" -in "$TMP/client.crt" \
      -certfile "$CERTS/ca.crt" -name "$NAME" -passout "pass:$P12_PASS" \
      -out "$CERTS/$NAME.p12"

    mv "$TMP/client.key" "$CERTS/$NAME.key"
    mv "$TMP/client.crt" "$CERTS/$NAME.crt"
    chmod 600 "$CERTS/$NAME.key" "$CERTS/$NAME.p12"

    echo "wrote: $CERTS/$NAME.p12  (import into your browser; p12 password = \$MTLS_CLIENT_P12_PASSWORD)"
    echo "wrote: $CERTS/$NAME.crt / $CERTS/$NAME.key  (for curl / API scripts)"
    echo "trust: $CERTS/ca.crt  as a root CA on every device"
    ;;
  *)
    echo "error: unknown command: $cmd" >&2; exit 1 ;;
esac
