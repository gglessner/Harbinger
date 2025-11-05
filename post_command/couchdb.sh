#!/bin/bash
# Apache CouchDB Security Scanner Chain
# Author: Garland Glessner <gglessner@gmail.com>
# License: GNU GPL
#
# Runs the full Apache CouchDB security scanning chain:
# 1. Port check
# 2. TLS detection  
# 3. Certificate collection
# 4. Apache CouchDB security testing
#
# Always returns 0 for successful chain execution, regardless of final couchdb.py result
# This allows harbinger to capture all logs while treating expected failures as success

set -e  # Exit on any error initially

# Check arguments
if [ $# -ne 2 ]; then
    echo "Usage: $0 <host> <port>" >&2
    exit 1
fi

HOST=$1
PORT=$2

echo "=== Apache CouchDB Security Scan Chain for $HOST:$PORT ==="

# Step 1: Port check
echo "Step 1: Port connectivity check..."
if python3 post_command/port_check.py "$HOST" "$PORT"; then
    echo "Port $PORT is open on $HOST"
else
    echo "Port $PORT is closed on $HOST - stopping chain"
    exit 0  # Return 0 - port closed is not an error
fi

# Step 2: TLS detection
echo ""
echo "Step 2: TLS capability detection..."
if python3 post_command/tls_check.py "$HOST" "$PORT"; then
    echo "TLS detected on $HOST:$PORT"
    TLS_DETECTED=true
else
    echo "No TLS detected on $HOST:$PORT"
    TLS_DETECTED=false
fi

# Step 3: Certificate collection (if TLS detected)
if [ "$TLS_DETECTED" = true ]; then
    echo ""
    echo "Step 3: Certificate collection..."
    if python3 post_command/cert_collector.py "$HOST" "$PORT"; then
        echo "Certificates collected for $HOST:$PORT"
    else
        echo "Certificate collection failed for $HOST:$PORT"
        # Continue anyway - maybe couchdb.py can still work
    fi
    
    # Step 4: Apache CouchDB TLS testing
    echo ""
    echo "Step 4: Apache CouchDB TLS security testing..."
    if python3 post_command/couchdb.py --tls "$HOST" "$PORT"; then
        echo "Apache CouchDB TLS connection successful"
    else
        echo "Apache CouchDB TLS connection failed (may not be a CouchDB service)"
    fi
else
    # Step 4: Apache CouchDB plain testing
    echo ""
    echo "Step 4: Apache CouchDB plain connection testing..."
    if python3 post_command/couchdb.py "$HOST" "$PORT"; then
        echo "Apache CouchDB plain connection successful"
    else
        echo "Apache CouchDB plain connection failed (may not be a CouchDB service)"
    fi
fi

echo ""
echo "=== Apache CouchDB Security Scan Chain Complete ==="

# Always return 0 - we want to capture all logs regardless of final result
# The individual steps above already logged their results
exit 0

