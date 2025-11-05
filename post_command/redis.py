#!/usr/bin/env python3
"""
Minimal Redis Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests Redis connectivity and reports security configuration:
- No authentication required (vulnerable)
- Authentication required (properly secured)
- TLS encryption status
- Basic Redis security posture
"""

import sys
import socket
import ssl
import time
import os
import argparse
try:
    import redis
    from redis.exceptions import ConnectionError, AuthenticationError, ResponseError
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

def test_redis_connection(host, port, use_ssl=False):
    """Test basic Redis connection"""
    try:
        if use_ssl:
            # Test with SSL/TLS
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
            # Test without SSL/TLS
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.close()
            return True
    except Exception:
        return False

def test_redis_auth(host, port, use_ssl=False, password=None):
    """Test Redis authentication and basic security"""
    if not REDIS_AVAILABLE:
        return {
            'success': False,
            'error': 'Redis Python module not available. Install with: pip install redis'
        }
    
    try:
        # Configure Redis connection
        config = {
            'host': host,
            'port': port,
            'socket_timeout': 5,
            'socket_connect_timeout': 5,
            'decode_responses': True
        }
        
        if use_ssl:
            # Check if truststore file exists for this host
            truststore_file = f'ca_certs/{host}-{port}.txt'
            if os.path.exists(truststore_file):
                config['ssl_cert_reqs'] = ssl.CERT_REQUIRED
                config['ssl_ca_certs'] = truststore_file
            else:
                # Fallback to no verification if no truststore
                config['ssl_cert_reqs'] = ssl.CERT_NONE
            
            config['ssl'] = True
        
        if password:
            config['password'] = password
        
        # Create Redis client
        r = redis.Redis(**config)
        
        # Test basic connection
        r.ping()
        
        # Get server info
        info = r.info()
        version = info.get('redis_version', 'Unknown')
        
        # Check authentication status
        auth_required = info.get('requirepass', '') != ''
        acl_enabled = info.get('acl_enabled', 0) == 1
        
        # Check protected mode
        protected_mode = info.get('protected_mode', 0) == 1
        
        # Check if bound to all interfaces
        bind_addresses = info.get('tcp_bind', '')
        bound_to_all = '*' in bind_addresses or '0.0.0.0' in bind_addresses
        
        # Check for dangerous commands
        dangerous_commands = []
        if r.exists('CONFIG'):
            dangerous_commands.append('CONFIG')
        if r.exists('FLUSHALL'):
            dangerous_commands.append('FLUSHALL')
        if r.exists('FLUSHDB'):
            dangerous_commands.append('FLUSHDB')
        if r.exists('EVAL'):
            dangerous_commands.append('EVAL')
        
        # Test write permission (create a test key)
        test_key = f'redis_security_test_{int(time.time())}'
        test_value = 'security_test_value'
        
        try:
            r.set(test_key, test_value, ex=60)  # Set with 60 second expiry
            write_permission = True
            
            # Test read permission
            retrieved_value = r.get(test_key)
            read_permission = retrieved_value == test_value
            
            # Test delete permission
            r.delete(test_key)
            delete_permission = True
            
        except Exception:
            write_permission = False
            read_permission = False
            delete_permission = False
        
        # Count keys
        try:
            key_count = r.dbsize()
        except Exception:
            key_count = 0
        
        return {
            'success': True,
            'version': version,
            'auth_required': auth_required,
            'acl_enabled': acl_enabled,
            'protected_mode': protected_mode,
            'bound_to_all': bound_to_all,
            'dangerous_commands': dangerous_commands,
            'write_permission': write_permission,
            'read_permission': read_permission,
            'delete_permission': delete_permission,
            'key_count': key_count
        }
        
    except AuthenticationError:
        return {
            'success': False,
            'error': 'Authentication required - Redis is properly secured'
        }
    except ConnectionError as e:
        error_msg = str(e).lower()
        if 'connection refused' in error_msg or 'connection reset' in error_msg:
            return {
                'success': False,
                'error': 'Connection refused - service not running'
            }
        elif 'timeout' in error_msg:
            return {
                'success': False,
                'error': 'Connection timeout - service not responding'
            }
        elif 'ssl' in error_msg or 'certificate' in error_msg:
            return {
                'success': False,
                'error': f'TLS connection failed - {str(e)}'
            }
        else:
            return {
                'success': False,
                'error': f'Connection failed - {str(e)}'
            }
    except Exception as e:
        error_msg = str(e).lower()
        if 'not a redis' in error_msg or 'wrong protocol' in error_msg:
            return {
                'success': False,
                'error': 'Not a Redis service - wrong protocol'
            }
        else:
            return {
                'success': False,
                'error': f'Redis error - {str(e)}'
            }

def scan_redis_security(host, port=6379, tls_only=False):
    """Scan Redis security configuration"""
    
    if tls_only:
        # Test only TLS/SSL connection
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        
        if test_redis_connection(host, port, use_ssl=True):
            result = test_redis_auth(host, port, use_ssl=True)
            
            if result['success']:
                print("TLS connection successful")
                print(f"Redis version: {result['version']}")
                
                # Security assessment
                if not result['auth_required']:
                    print("SECURITY ISSUE: No authentication required")
                    print("VULNERABLE")
                else:
                    print("Authentication is required (good)")
                
                if not result['protected_mode']:
                    print("SECURITY ISSUE: Protected mode disabled")
                else:
                    print("Protected mode enabled (good)")
                
                if result['bound_to_all']:
                    print("SECURITY ISSUE: Bound to all interfaces")
                else:
                    print("Bound to specific interfaces (good)")
                
                if result['dangerous_commands']:
                    print(f"SECURITY ISSUE: Dangerous commands available: {', '.join(result['dangerous_commands'])}")
                
                # Permission summary
                perms = []
                if result['write_permission']:
                    perms.append("WRITE")
                if result['read_permission']:
                    perms.append("READ")
                if result['delete_permission']:
                    perms.append("DELETE")
                
                if perms:
                    print(f"Permissions: {', '.join(perms)}")
                
                print(f"Keys in database: {result['key_count']}")
                return
            else:
                print(result['error'])
                return
        else:
            print("TLS connection failed")
            return
    
    # Default behavior - test only plain connection (no TLS)
    print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
    
    if test_redis_connection(host, port, use_ssl=False):
        result = test_redis_auth(host, port, use_ssl=False)
        
        if result['success']:
            print("Plain connection successful")
            print(f"Redis version: {result['version']}")
            
            # Security assessment
            if not result['auth_required']:
                print("SECURITY ISSUE: No authentication required")
                print("VULNERABLE")
            else:
                print("Authentication is required (good)")
            
            if not result['protected_mode']:
                print("SECURITY ISSUE: Protected mode disabled")
            else:
                print("Protected mode enabled (good)")
            
            if result['bound_to_all']:
                print("SECURITY ISSUE: Bound to all interfaces")
            else:
                print("Bound to specific interfaces (good)")
            
            if result['dangerous_commands']:
                print(f"SECURITY ISSUE: Dangerous commands available: {', '.join(result['dangerous_commands'])}")
            
            # Permission summary
            perms = []
            if result['write_permission']:
                perms.append("WRITE")
            if result['read_permission']:
                perms.append("READ")
            if result['delete_permission']:
                perms.append("DELETE")
            
            if perms:
                print(f"Permissions: {', '.join(perms)}")
            
            print(f"Keys in database: {result['key_count']}")
            return
        else:
            print(result['error'])
            return
    else:
        print("Plain connection failed")
        return

def main():
    parser = argparse.ArgumentParser(description='Redis Security Scanner')
    parser.add_argument('host', help='Redis host to test')
    parser.add_argument('port', nargs='?', type=int, default=6379, help='Redis port (default: 6379)')
    parser.add_argument('--tls', '-t', action='store_true', help='Test TLS/SSL connection only')
    
    args = parser.parse_args()
    
    host = args.host
    port = args.port
    tls_only = args.tls
    
    # Check if port is specified in host (host:port format)
    if ':' in host:
        host, port_str = host.split(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            print(f"Error: Invalid port '{port_str}'", file=sys.stderr)
            sys.exit(1)
    
    scan_redis_security(host, port, tls_only)

if __name__ == '__main__':
    main()
