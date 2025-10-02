#!/usr/bin/env python3
"""
HTTP GET Request Check Script
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

Performs HTTP GET request to specified path and outputs server response including headers.
Returns exit code 0 for successful response, 1 for failure.

Usage: python http_check.py <host> <port> [--tls] [--url <path>]
"""

import sys
import socket
import ssl
import time
import argparse

def send_http_request(host, port, use_tls=False, url_path='/', timeout=10):
    """
    Send HTTP GET request to specified path and return response.
    Returns tuple: (status, message) where status is 'success' or 'error'
    """
    try:
        # Create socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Connect to host:port
        sock.connect((host, port))
        
        # Wrap with SSL if TLS is enabled
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
        
        # Ensure URL path starts with /
        if not url_path.startswith('/'):
            url_path = '/' + url_path
        
        # Construct HTTP GET request
        request = f"GET {url_path} HTTP/1.1\r\n"
        request += f"Host: {host}:{port}\r\n"
        request += "User-Agent: Harbinger-HTTP-Check/1.0\r\n"
        request += "Connection: close\r\n"
        request += "\r\n"
        
        # Send request
        sock.send(request.encode('utf-8'))
        
        # Receive response
        response_data = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
            except socket.timeout:
                break
        
        sock.close()
        
        # Parse and format response
        if response_data:
            response_text = response_data.decode('utf-8', errors='replace')
            return ('success', response_text)
        else:
            return ('error', 'No response received')
            
    except socket.timeout:
        return ('error', 'Connection timed out')
    except (ssl.SSLError, socket.error, ConnectionError, TimeoutError) as e:
        return ('error', f'Connection failed: {str(e)}')
    except Exception as e:
        return ('error', f'Request failed: {str(e)}')

def main():
    parser = argparse.ArgumentParser(description='HTTP GET Request Check Script')
    parser.add_argument('host', help='Host to connect to')
    parser.add_argument('port', type=int, help='Port number')
    parser.add_argument('--tls', '-t', action='store_true', help='Use TLS/HTTPS')
    parser.add_argument('--url', '-u', default='/', help='URL path from root (default: /)')
    
    args = parser.parse_args()
    
    host = args.host
    port = args.port
    use_tls = args.tls
    url_path = args.url
    
    # Validate port number
    if not (1 <= port <= 65535):
        print(f"Error: Port must be between 1 and 65535", file=sys.stderr)
        sys.exit(1)
    
    # Perform the HTTP request
    status, message = send_http_request(host, port, use_tls, url_path)
    
    # Print the result
    print(message)
    
    # Return appropriate exit code
    if status == 'success':
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()

