#!/usr/bin/env python3
"""
Minimal Kafka Security Scanner
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

This script tests Kafka connectivity and reports security configuration:
- No vulnerability detected (properly secured)
- No encryption and no authentication (vulnerable)
- Encryption and no authentication (partially secured)
"""

import sys
import socket
import ssl
import time
import os
import argparse
from confluent_kafka import Consumer, Producer, KafkaError, KafkaException

def test_kafka_connection(host, port, use_ssl=False):
    """Test basic Kafka connection"""
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

def test_kafka_consumer(host, port, use_ssl=False):
    """Test Kafka consumer connection"""
    try:
        config = {
            'bootstrap.servers': f'{host}:{port}',
            'group.id': 'security-test',
            'auto.offset.reset': 'earliest',
            'session.timeout.ms': 5000,
            'request.timeout.ms': 5000,
            'metadata.max.age.ms': 5000,
        }
        
        if use_ssl:
            # Check if truststore file exists for this host
            truststore_file = f'ca_certs/{host}-{port}.pem'
            if os.path.exists(truststore_file):
                config.update({
                    'security.protocol': 'SSL',
                    'ssl.ca.location': truststore_file,
                })
            else:
                # Fallback to no verification if no truststore
                config.update({
                    'security.protocol': 'SSL',
                })
        
        consumer = Consumer(config)
        
        # Try to get metadata
        metadata = consumer.list_topics(timeout=5)
        consumer.close()
        return True, None
    except Exception as e:
        error_msg = str(e).lower()
        if 'connection refused' in error_msg or 'connection reset' in error_msg:
            return False, 'Connection refused - service not running'
        elif 'timeout' in error_msg:
            return False, 'Connection timeout - service not responding'
        elif 'ssl' in error_msg or 'certificate' in error_msg:
            return False, f'TLS connection failed - {str(e)}'
        elif 'authentication' in error_msg or 'authorization' in error_msg:
            return False, f'Authentication failed - {str(e)}'
        else:
            return False, f'Not a Kafka service - {str(e)}'

def test_kafka_producer(host, port, use_ssl=False):
    """Test Kafka producer connection"""
    try:
        config = {
            'bootstrap.servers': f'{host}:{port}',
            'request.timeout.ms': 5000,
            'metadata.max.age.ms': 5000,
        }
        
        if use_ssl:
            # Check if truststore file exists for this host
            truststore_file = f'ca_certs/{host}-{port}.pem'
            if os.path.exists(truststore_file):
                config.update({
                    'security.protocol': 'SSL',
                    'ssl.ca.location': truststore_file,
                })
            else:
                # Fallback to no verification if no truststore
                config.update({
                    'security.protocol': 'SSL',
                })
        
        producer = Producer(config)
        
        # Try to get metadata
        metadata = producer.list_topics(timeout=5)
        producer.flush()
        return True, None
    except Exception as e:
        error_msg = str(e).lower()
        if 'connection refused' in error_msg or 'connection reset' in error_msg:
            return False, 'Connection refused - service not running'
        elif 'timeout' in error_msg:
            return False, 'Connection timeout - service not responding'
        elif 'ssl' in error_msg or 'certificate' in error_msg:
            return False, f'TLS connection failed - {str(e)}'
        elif 'authentication' in error_msg or 'authorization' in error_msg:
            return False, f'Authentication failed - {str(e)}'
        else:
            return False, f'Not a Kafka service - {str(e)}'

def scan_kafka_security(host, port=9092, tls_only=False):
    """Scan Kafka security configuration"""
    
    if tls_only:
        # Test only TLS/SSL connection
        print(f"Testing {host}:{port} - TLS only...", file=sys.stderr)
        
        if test_kafka_connection(host, port, use_ssl=True):
            consumer_success, consumer_error = test_kafka_consumer(host, port, use_ssl=True)
            producer_success, producer_error = test_kafka_producer(host, port, use_ssl=True)
            
            if consumer_success or producer_success:
                print("TLS connection successful")
                return
            else:
                # Show the most specific error message
                if consumer_error and producer_error:
                    error_msg = consumer_error if len(consumer_error) < len(producer_error) else producer_error
                else:
                    error_msg = consumer_error or producer_error or "TLS connection failed"
                print(error_msg)
                return
        else:
            print("TLS connection failed")
            return
    
    # Default behavior - test only plain connection (no TLS)
    print(f"Testing {host}:{port} - Plain connection...", file=sys.stderr)
    
    if test_kafka_connection(host, port, use_ssl=False):
        consumer_success, consumer_error = test_kafka_consumer(host, port, use_ssl=False)
        producer_success, producer_error = test_kafka_producer(host, port, use_ssl=False)
        
        if consumer_success or producer_success:
            print("Plain connection successful")
            return
        else:
            # Show the most specific error message
            if consumer_error and producer_error:
                error_msg = consumer_error if len(consumer_error) < len(producer_error) else producer_error
            else:
                error_msg = consumer_error or producer_error or "Plain connection failed"
            print(error_msg)
            return
    else:
        print("Plain connection failed")
        return

def main():
    parser = argparse.ArgumentParser(description='Kafka Security Scanner')
    parser.add_argument('host', help='Kafka host to test')
    parser.add_argument('port', nargs='?', type=int, default=9092, help='Kafka port (default: 9092)')
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
    
    scan_kafka_security(host, port, tls_only)

if __name__ == '__main__':
    main()
