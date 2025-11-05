#!/bin/bash
# LDAP Security Scanner Chain
# Author: Garland Glessner <gglessner@gmail.com>
# License: GNU GPL
#
# Runs the full LDAP security scanning chain:
# 1. Port check
# 2. TLS detection  
# 3. Certificate collection
# 4. LDAP security testing
#
# Always returns 0 for successful chain execution, regardless of final ldap.py result

set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <host> <port>" >&2
    exit 1
fi

HOST=$1
PORT=$2

echo "=== LDAP Security Scan Chain for $HOST:$PORT ==="

echo "Step 1: Port connectivity check..."
if python3 post_command/port_check.py "$HOST" "$PORT"; then
    echo "✓ Port $PORT is open on $HOST"
else
    echo "✗ Port $PORT is closed on $HOST - stopping chain"
    exit 0
fi

echo ""
echo "Step 2: TLS capability detection..."
if python3 post_command/tls_check.py "$HOST" "$PORT"; then
    echo "✓ TLS detected on $HOST:$PORT"
    TLS_DETECTED=true
else
    echo "✗ No TLS detected on $HOST:$PORT"
    TLS_DETECTED=false
fi

if [ "$TLS_DETECTED" = true ]; then
    echo ""
    echo "Step 3: Certificate collection..."
    if python3 post_command/cert_collector.py "$HOST" "$PORT"; then
        echo "✓ Certificates collected for $HOST:$PORT"
    else
        echo "✗ Certificate collection failed for $HOST:$PORT"
    fi
    
    echo ""
    echo "Step 4: LDAP TLS security testing..."
    if python3 post_command/ldap.py --tls "$HOST" "$PORT"; then
        echo "✓ LDAP TLS connection successful"
    else
        echo "✗ LDAP TLS connection failed (may not be an LDAP service)"
    fi
else
    echo ""
    echo "Step 4: LDAP plain connection testing..."
    if python3 post_command/ldap.py "$HOST" "$PORT"; then
        echo "✓ LDAP plain connection successful"
    else
        echo "✗ LDAP plain connection failed (may not be an LDAP service)"
    fi
fi

echo ""
echo "=== LDAP Security Scan Chain Complete ==="
exit 0

