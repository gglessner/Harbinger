#!/bin/bash
# Docker API Security Scanner Chain
# Author: Garland Glessner <gglessner@gmail.com>
# License: GNU GPL
#
# Runs the full Docker API security scanning chain:
# 1. Port check
# 2. TLS detection  
# 3. Certificate collection
# 4. Docker API security testing
#
# Always returns 0 for successful chain execution, regardless of final docker-api.py result

set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <host> <port>" >&2
    exit 1
fi

HOST=$1
PORT=$2

echo "=== Docker API Security Scan Chain for $HOST:$PORT ==="

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
    echo "Step 4: Docker API TLS security testing..."
    if python3 post_command/docker-api.py --tls "$HOST" "$PORT"; then
        echo "✓ Docker API TLS connection successful"
    else
        echo "✗ Docker API TLS connection failed (may not be a Docker API service)"
    fi
else
    echo ""
    echo "Step 4: Docker API plain connection testing..."
    if python3 post_command/docker-api.py "$HOST" "$PORT"; then
        echo "✓ Docker API plain connection successful"
    else
        echo "✗ Docker API plain connection failed (may not be a Docker API service)"
    fi
fi

echo ""
echo "=== Docker API Security Scan Chain Complete ==="
exit 0

