#!/bin/bash
# InfluxDB Chronograf Security Scanner Chain
# Author: Garland Glessner <gglessner@gmail.com>
# License: GNU GPL
#
# Runs the full InfluxDB Chronograf security scanning chain:
# 1. Port check
# 2. TLS detection  
# 3. Certificate collection
# 4. InfluxDB Chronograf security testing
#
# Always returns 0 for successful chain execution, regardless of final chronograf.py result
# This allows harbinger to capture all logs while treating expected failures as success

set -e  # Exit on any error initially

# Check arguments
if [ $# -ne 2 ]; then
    echo "Usage: $0 <host> <port>" >&2
    exit 1
fi

HOST=$1
PORT=$2

echo "=== InfluxDB Chronograf Security Scan Chain for $HOST:$PORT ==="

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
        # Continue anyway - maybe chronograf.py can still work
    fi
    
    # Step 4: InfluxDB Chronograf TLS testing
    echo ""
    echo "Step 4: InfluxDB Chronograf TLS security testing..."
    if python3 post_command/chronograf.py --tls "$HOST" "$PORT"; then
        echo "InfluxDB Chronograf TLS connection successful"
    else
        echo "InfluxDB Chronograf TLS connection failed (may not be a Chronograf service)"
    fi
else
    # Step 4: InfluxDB Chronograf plain testing
    echo ""
    echo "Step 4: InfluxDB Chronograf plain connection testing..."
    if python3 post_command/chronograf.py "$HOST" "$PORT"; then
        echo "InfluxDB Chronograf plain connection successful"
    else
        echo "InfluxDB Chronograf plain connection failed (may not be a Chronograf service)"
    fi
fi

echo ""
echo "=== InfluxDB Chronograf Security Scan Chain Complete ==="

# Always return 0 - we want to capture all logs regardless of final result
# The individual steps above already logged their results
exit 0

