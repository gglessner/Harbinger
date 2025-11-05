#!/usr/bin/env python3
"""
Apache Karaf SSH Console Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests Apache Karaf SSH Console connectivity and reports security configuration:
- Default credentials work (vulnerable)
- Authentication required (properly secured)
"""

import sys
import socket
import ssl
import argparse
import paramiko

def test_karaf_ssh_connection(host, port, use_ssl=False):
    """Test basic Karaf SSH connection"""
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

def test_karaf_ssh_auth(host, port, use_ssl=False):
    """Test Karaf SSH authentication"""
    try:
        # Try default credentials
        default_creds = [
            ('karaf', 'karaf'),
            ('admin', 'admin'),
            ('karaf', ''),
            ('', ''),
        ]
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        for username, password in default_creds:
            try:
                client.connect(
                    hostname=host,
                    port=port,
                    username=username,
                    password=password,
                    timeout=5,
                    look_for_keys=False,
                    allow_agent=False
                )
                client.close()
                print(f"Apache Karaf SSH Console accessible at {host}:{port}")
                print(f"VULNERABLE: Default credentials work (username: {username if username else '(empty)'}, password: {'*' * len(password) if password else '(empty)'})")
                print("VULNERABLE")
                return True
            except paramiko.AuthenticationException:
                continue
            except Exception:
                break
        
        client.close()
        
        # If we got here, authentication failed for all default credentials
        # Try to connect without credentials to see if no auth is required
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=host,
                port=port,
                username='',
                password='',
                timeout=5,
                look_for_keys=False,
                allow_agent=False
            )
            client.close()
            print(f"Apache Karaf SSH Console accessible at {host}:{port}")
            print("VULNERABLE")
            return True
        except Exception:
            pass
        
        print(f"Apache Karaf SSH Console at {host}:{port} requires authentication")
        return False
        
    except ImportError:
        print("Error: paramiko library not available. Install with: pip install paramiko")
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
            print(f"Error testing Karaf SSH: {str(e)}")
        return False

def scan_karaf_ssh_security(host, port=8101, tls_only=False):
    """Scan Karaf SSH security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        if test_karaf_ssh_connection(host, port, use_ssl=True):
            test_karaf_ssh_auth(host, port, use_ssl=True)
        else:
            print("TLS connection failed")
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        if test_karaf_ssh_connection(host, port, use_ssl=False):
            test_karaf_ssh_auth(host, port, use_ssl=False)
        else:
            print("Plain connection failed")

def main():
    parser = argparse.ArgumentParser(description='Apache Karaf SSH Console Security Scanner')
    parser.add_argument('host', help='Karaf SSH host to test')
    parser.add_argument('port', nargs='?', type=int, default=8101, help='Karaf SSH port (default: 8101)')
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
    
    scan_karaf_ssh_security(host, port, tls_only)

if __name__ == '__main__':
    main()

