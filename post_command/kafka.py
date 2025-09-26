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
            config.update({
                'security.protocol': 'SSL',
                'ssl.check.hostname': False,
                'ssl.verify': False,
            })
        
        consumer = Consumer(config)
        
        # Try to get metadata
        metadata = consumer.list_topics(timeout=5)
        consumer.close()
        return True
    except Exception:
        return False

def test_kafka_producer(host, port, use_ssl=False):
    """Test Kafka producer connection"""
    try:
        config = {
            'bootstrap.servers': f'{host}:{port}',
            'request.timeout.ms': 5000,
            'metadata.max.age.ms': 5000,
        }
        
        if use_ssl:
            config.update({
                'security.protocol': 'SSL',
                'ssl.check.hostname': False,
                'ssl.verify': False,
            })
        
        producer = Producer(config)
        
        # Try to get metadata
        metadata = producer.list_topics(timeout=5)
        producer.flush()
        return True
    except Exception:
        return False

def scan_kafka_security(host, port=9092):
    """Scan Kafka security configuration"""
    
    # Test 1: No encryption, no authentication
    print(f"Testing {host}:{port} - No encryption, no authentication...", file=sys.stderr)
    
    if test_kafka_connection(host, port, use_ssl=False):
        if test_kafka_consumer(host, port, use_ssl=False) or test_kafka_producer(host, port, use_ssl=False):
            print("No encryption and no authentication")
            return
    
    # Test 2: Encryption, no authentication
    print(f"Testing {host}:{port} - Encryption, no authentication...", file=sys.stderr)
    
    if test_kafka_connection(host, port, use_ssl=True):
        if test_kafka_consumer(host, port, use_ssl=True) or test_kafka_producer(host, port, use_ssl=True):
            print("Encryption and no authentication")
            return
    
    # If we get here, no connection was possible
    print("No vulnerability detected")

def main():
    if len(sys.argv) < 2:
        print("Usage: kafka.py <host> [port]", file=sys.stderr)
        print("       kafka.py <host:port>", file=sys.stderr)
        sys.exit(1)
    
    host = sys.argv[1]
    port = 9092  # Default Kafka port
    
    # Check if port is specified as second argument
    if len(sys.argv) == 3:
        port = int(sys.argv[2])
    # Check if port is specified in host (host:port format)
    elif ':' in host:
        host, port = host.split(':', 1)
        port = int(port)
    
    scan_kafka_security(host, port)

if __name__ == '__main__':
    main()
