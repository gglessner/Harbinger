#!/bin/bash
# InfluxDB Security Scanner Chain
# Author: Garland Glessner <gglessner@gmail.com>
# License: GNU GPL
#
# Runs the full InfluxDB security scanning chain:
# 1. Port check
# 2. TLS detection  
# 3. Certificate collection
# 4. InfluxDB security testing
#
# Always returns 0 for successful chain execution, regardless of final influxdb.py result
# This allows harbinger to capture all logs while treating expected failures as success

set -e  # Exit on any error initially

# Check arguments
if [ $# -ne 2 ]; then
    echo "Usage: $0 <host> <port>" >&2
    exit 1
fi

HOST=$1
PORT=$2

echo "=== InfluxDB Security Scan Chain for $HOST:$PORT ==="

# Step 1: Port check
echo "Step 1: Port connectivity check..."
if python3 post_command/port_check.py "$HOST" "$PORT"; then
    echo "✓ Port $PORT is open on $HOST"
else
    echo "✗ Port $PORT is closed on $HOST - stopping chain"
    exit 0  # Return 0 - port closed is not an error
fi

# Step 2: TLS detection
echo ""
echo "Step 2: TLS capability detection..."
if python3 post_command/tls_check.py "$HOST" "$PORT"; then
    echo "✓ TLS detected on $HOST:$PORT"
    TLS_DETECTED=true
else
    echo "✗ No TLS detected on $HOST:$PORT"
    TLS_DETECTED=false
fi

# Step 3: Certificate collection (if TLS detected)
if [ "$TLS_DETECTED" = true ]; then
    echo ""
    echo "Step 3: Certificate collection..."
    if python3 post_command/cert_collector.py "$HOST" "$PORT"; then
        echo "✓ Certificates collected for $HOST:$PORT"
    else
        echo "✗ Certificate collection failed for $HOST:$PORT"
        # Continue anyway - maybe influxdb.py can still work
    fi
    
    # Step 4: InfluxDB TLS testing
    echo ""
    echo "Step 4: InfluxDB TLS security testing..."
    if python3 post_command/influxdb.py --tls "$HOST" "$PORT"; then
        echo "✓ InfluxDB TLS connection successful"
    else
        echo "✗ InfluxDB TLS connection failed (may not be an InfluxDB service)"
    fi
else
    # Step 4: InfluxDB plain testing
    echo ""
    echo "Step 4: InfluxDB plain connection testing..."
    if python3 post_command/influxdb.py "$HOST" "$PORT"; then
        echo "✓ InfluxDB plain connection successful"
    else
        echo "✗ InfluxDB plain connection failed (may not be an InfluxDB service)"
    fi
fi

echo ""
echo "=== InfluxDB Security Scan Chain Complete ==="

# Always return 0 - we want to capture all logs regardless of final result
# The individual steps above already logged their results
exit 0

