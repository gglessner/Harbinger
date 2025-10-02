#!/usr/bin/env python3
"""
TLS Connectivity Check Script
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

Quick OpenSSL-based TLS connection check.
Returns exit code 0 for successful TLS connection, 1 for non-TLS or failed connection.

Usage: python tls_check.py <host> <port>
"""

import sys
import subprocess
import socket
import ssl

def openssl_tls_check(host, port):
    """
    Perform TLS connection check using openssl s_client.
    Returns tuple: (status, message) where status is 'tls' or 'no_tls'
    """
    try:
        # Use openssl s_client with optimized settings for speed
        # -connect: Connect to host:port
        # -quiet: Suppress verbose output
        # -servername: Set SNI (Server Name Indication) for proper TLS handshake
        # Note: We don't use -verify_return_error because we want to detect TLS even with invalid certificates
        command = [
            'openssl', 's_client', '-connect', f'{host}:{port}',
            '-quiet', '-servername', host
        ]
        
        # Send QUIT command and capture output
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Send QUIT command and capture output with a shorter timeout
        try:
            stdout, stderr = process.communicate(input='Q\n', timeout=5)
        except subprocess.TimeoutExpired:
            # If timeout, kill the process and get partial output
            process.kill()
            stdout, stderr = process.communicate()
        
        # Check if TLS handshake was successful by looking for TLS-related output
        # Even if certificate verification fails, we still have a TLS connection
        output = stdout + stderr
        
        # Look for indicators of successful TLS handshake
        tls_indicators = [
            'verify return:',
            'Verify return code:',
            'SSL-Session:',
            'Protocol  :',
            'Cipher    :',
            'CONNECTED(',
            'New, TLS',
            'depth=',
            'CN='
        ]
        
        # Check if any TLS indicators are present in the output
        for indicator in tls_indicators:
            if indicator in output:
                return ('tls', 'TLS detected')
        
        # If no TLS indicators found, it's likely not a TLS service
        return ('no_tls', 'TLS not detected')
        
    except subprocess.TimeoutExpired:
        return ('no_tls', 'TLS not detected')
    except (subprocess.CalledProcessError, FileNotFoundError):
        # If openssl fails, fall back to Python SSL check
        return python_ssl_check(host, port)

def python_ssl_check(host, port):
    """
    Fallback method using Python's SSL module if openssl fails.
    Returns tuple: (status, message) where status is 'tls' or 'no_tls'
    """
    try:
        # Create socket and wrap with SSL
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)  # 5 second timeout
            
            # Connect to host:port
            sock.connect((host, port))
            
            # Wrap with SSL context (no certificate verification for speed)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Try to establish SSL connection
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            
            # If we get here, TLS connection was successful
            ssl_sock.close()
            return ('tls', 'TLS detected')
            
    except socket.timeout:
        return ('no_tls', 'TLS not detected')
    except (ssl.SSLError, socket.error, ConnectionError, TimeoutError):
        return ('no_tls', 'TLS not detected')
    except Exception:
        return ('no_tls', 'TLS not detected')

def main():
    if len(sys.argv) != 3:
        print("Usage: python tls_check.py <host> <port>", file=sys.stderr)
        sys.exit(1)
    
    host = sys.argv[1]
    port = sys.argv[2]
    
    # Validate port number
    try:
        port = int(port)
        if not (1 <= port <= 65535):
            print(f"Error: Port must be between 1 and 65535", file=sys.stderr)
            sys.exit(1)
    except ValueError:
        print(f"Error: Invalid port number: {port}", file=sys.stderr)
        sys.exit(1)
    
    # Perform the check
    status, message = openssl_tls_check(host, port)
    
    # Print the result message
    print(message)
    
    # Return appropriate exit code
    if status == 'tls':
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
