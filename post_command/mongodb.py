#!/usr/bin/env python3
"""
MongoDB Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests MongoDB connectivity and reports security configuration:
- No authentication required (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import struct

def test_mongodb_connection(host, port, use_ssl=False):
    """Test basic MongoDB connection"""
    try:
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            wrapped_socket = context.wrap_socket(sock, server_hostname=host)
            wrapped_socket.connect((host, port))
            wrapped_socket.close()
            return True
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.close()
            return True
    except Exception:
        return False

def test_mongodb_auth(host, port, use_ssl=False):
    """Test MongoDB authentication"""
    try:
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            conn = context.wrap_socket(sock, server_hostname=host)
            conn.connect((host, port))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            conn = sock
            conn.connect((host, port))
        
        # MongoDB Wire Protocol: OP_MSG (2013) or OP_QUERY (legacy)
        # Try to send a simple isMaster command without authentication
        # Format: messageLength (4 bytes) + requestID (4 bytes) + responseTo (4 bytes) + opCode (4 bytes) + message
        
        # OP_MSG format (simplified)
        # Try isMaster command
        message = b'\x00\x00\x00\x00'  # flagBits
        message += b'\x00'  # section kind (0 = body)
        message += b'\x00\x00\x00\x00'  # document size placeholder
        
        # Build isMaster command document
        import json
        cmd = {"isMaster": 1}
        cmd_bytes = json.dumps(cmd).encode('utf-8')
        
        # Simple approach: send minimal isMaster request
        # MongoDB Wire Protocol header: 16 bytes
        request_id = 1
        response_to = 0
        op_code = 2013  # OP_MSG
        
        msg_length = 16 + len(message) + len(cmd_bytes)
        
        header = struct.pack('<I', msg_length)  # messageLength
        header += struct.pack('<I', request_id)  # requestID
        header += struct.pack('<I', response_to)  # responseTo
        header += struct.pack('<I', op_code)  # opCode
        
        # Send header + message
        conn.send(header + message[:4] + struct.pack('<I', len(cmd_bytes) + 4) + cmd_bytes)
        
        # Read response
        response = conn.recv(4096)
        conn.close()
        
        # Check if we got a response (connection successful)
        if len(response) > 16:
            # If we got a response, MongoDB is accessible
            # Check if response contains authentication error
            response_str = response.decode('utf-8', errors='ignore')
            if 'authentication' in response_str.lower() or 'unauthorized' in response_str.lower():
                print(f"MongoDB at {host}:{port} requires authentication")
                return False
            else:
                print(f"MongoDB accessible at {host}:{port}")
                print("VULNERABLE: No authentication required")
                print("VULNERABLE")
                return True
        
        return False
        
    except socket.timeout:
        print(f"Connection timeout - service not responding")
        return False
    except ConnectionRefusedError:
        print(f"Connection refused - service not running on {host}:{port}")
        return False
    except Exception as e:
        error_msg = str(e).lower()
        if 'connection refused' in error_msg or 'connection reset' in error_msg:
            print(f"Connection refused - service not running on {host}:{port}")
        elif 'timeout' in error_msg:
            print(f"Connection timeout - service not responding")
        else:
            # Try with pymongo if available
            try:
                import pymongo
                try:
                    if use_ssl:
                        client = pymongo.MongoClient(f"mongodb://{host}:{port}/", ssl=True, ssl_cert_reqs=ssl.CERT_NONE, serverSelectionTimeoutMS=5000)
                    else:
                        client = pymongo.MongoClient(f"mongodb://{host}:{port}/", serverSelectionTimeoutMS=5000)
                    # Try to access server info without authentication
                    info = client.server_info()
                    client.close()
                    print(f"MongoDB accessible at {host}:{port}")
                    print("VULNERABLE: No authentication required")
                    print("VULNERABLE")
                    return True
                except pymongo.errors.OperationFailure as auth_err:
                    if 'authentication' in str(auth_err).lower() or 'unauthorized' in str(auth_err).lower():
                        print(f"MongoDB at {host}:{port} requires authentication")
                        return False
                    else:
                        print(f"Error testing MongoDB: {str(auth_err)}")
                        return False
                except Exception as db_err:
                    print(f"Error testing MongoDB: {str(db_err)}")
                    return False
            except ImportError:
                print(f"Error testing MongoDB: {str(e)}")
                return False
        return False

def scan_mongodb_security(host, port=27017, tls_only=False):
    """Scan MongoDB security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_mongodb_connection(host, port, use_ssl=True):
            test_mongodb_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_mongodb_connection(host, port, use_ssl=False):
            test_mongodb_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='MongoDB Security Scanner')
    parser.add_argument('host', help='MongoDB host to test')
    parser.add_argument('port', nargs='?', type=int, default=27017, help='MongoDB port (default: 27017)')
    parser.add_argument('--tls', '-t', action='store_true', help='Test TLS/SSL connection only')
    
    args = parser.parse_args()
    
    host = args.host
    port = args.port
    tls_only = args.tls
    
    if ':' in host:
        host, port_str = host.split(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            print(f"Error: Invalid port '{port_str}'", file=sys.stderr)
            sys.exit(1)
    
    scan_mongodb_security(host, port, tls_only)

if __name__ == '__main__':
    main()

