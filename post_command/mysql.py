#!/usr/bin/env python3
"""
MySQL Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests MySQL connectivity and reports security configuration:
- No authentication required (vulnerable)
- Default/weak credentials (vulnerable)
- Authentication required (properly secured)

Requires: mysql-connector-python OR PyMySQL
Install via:
  - pip: pip install mysql-connector-python (or pip install PyMySQL)
  - apt: sudo apt install python3-pymysql (Kali/Debian/Ubuntu)
  - MySQL APT repo: sudo apt install mysql-connector-python
"""

import sys
import argparse

# Try mysql-connector-python (required)
try:
    import mysql.connector
    from mysql.connector import Error
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False
    print("Error: mysql-connector-python is required.", file=sys.stderr)
    print("Install options for Kali Linux:", file=sys.stderr)
    print("  1. Add MySQL APT repository (recommended if pip unavailable):", file=sys.stderr)
    print("     wget https://dev.mysql.com/get/mysql-apt-config_0.8.22-1_all.deb", file=sys.stderr)
    print("     sudo dpkg -i mysql-apt-config_0.8.22-1_all.deb", file=sys.stderr)
    print("     sudo apt-get update", file=sys.stderr)
    print("     sudo apt-get install mysql-connector-python", file=sys.stderr)
    print("  2. pip install mysql-connector-python (if pip is available)", file=sys.stderr)
    print("  3. Download from: https://dev.mysql.com/downloads/connector/python/", file=sys.stderr)
    print("     Then: python3 setup.py install", file=sys.stderr)
    sys.exit(1)

def test_mysql_auth(host, port, use_ssl=False):
    """Test MySQL authentication using mysql-connector-python"""
    
    # Common default credentials to test
    test_credentials = [
        ('root', ''),           # Empty password (very common default)
        ('root', 'root'),       # root/root
        ('root', 'password'),   # root/password
        ('root', 'admin'),      # root/admin
        ('admin', ''),          # admin with empty password
        ('admin', 'admin'),     # admin/admin
        ('', ''),               # Empty user/password
    ]
    
    auth_required = False
    
    for username, password in test_credentials:
        try:
            connection_params = {
                'host': host,
                'port': port,
                'user': username,
                'password': password,
                'connection_timeout': 5,
                'autocommit': True
            }
            
            if use_ssl:
                connection_params['ssl_disabled'] = False
                connection_params['ssl_verify_cert'] = False
                connection_params['ssl_verify_identity'] = False
            else:
                connection_params['ssl_disabled'] = True
            
            conn = mysql.connector.connect(**connection_params)
            
            if conn.is_connected():
                # Successfully connected - check if we can execute a query
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                cursor.fetchone()
                cursor.close()
                conn.close()
                
                # If we got here, authentication worked
                if username == '' and password == '':
                    print(f"MySQL accessible at {host}:{port}")
                    print("VULNERABLE: No authentication required")
                    print("VULNERABLE")
                    return True
                else:
                    print(f"MySQL accessible at {host}:{port}")
                    print(f"VULNERABLE: Default credentials working (user: '{username}', password: '{password}')")
                    print("VULNERABLE")
                    return True
                    
        except Error as e:
            error_msg = str(e).lower()
            error_code = e.errno if hasattr(e, 'errno') else None
            
            # MySQL error codes:
            # 1045 = Access denied (authentication required)
            # 2003 = Can't connect to MySQL server
            # 2006 = MySQL server has gone away
            # 2013 = Lost connection to MySQL server
            
            if error_code == 1045:
                # Access denied - authentication is required
                auth_required = True
                continue  # Try next credential
            elif error_code in (2003, 2006, 2013):
                # Connection issues
                print(f"Connection error - service not responding properly: {str(e)}")
                return False
            else:
                # Other errors - might be connection issues
                if 'connection' in error_msg or 'timeout' in error_msg:
                    print(f"Connection error: {str(e)}")
                    return False
                continue  # Try next credential
                
        except Exception as e:
            error_msg = str(e).lower()
            if 'connection refused' in error_msg or 'connection reset' in error_msg:
                print(f"Connection refused - service not running on {host}:{port}")
                return False
            elif 'timeout' in error_msg:
                print(f"Connection timeout - service not responding")
                return False
            continue  # Try next credential
    
    # If we tried all credentials and none worked
    if auth_required:
        print(f"MySQL at {host}:{port} requires authentication")
        return False
    else:
        print(f"MySQL accessible at {host}:{port}")
        print("Could not determine authentication status")
        return False

def scan_mysql_security(host, port=3306, tls_only=False):
    """Scan MySQL security configuration"""
    
    if tls_only:
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        test_mysql_auth(host, port, use_ssl=True)
    else:
        print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
        test_mysql_auth(host, port, use_ssl=False)

def main():
    parser = argparse.ArgumentParser(description='MySQL Security Scanner')
    parser.add_argument('host', help='MySQL host to test')
    parser.add_argument('port', nargs='?', type=int, default=3306, help='MySQL port (default: 3306)')
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
    
    scan_mysql_security(host, port, tls_only)

if __name__ == '__main__':
    main()

