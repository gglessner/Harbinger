#!/usr/bin/env python3
"""
Certificate Collector Script
Author: Garland Glessner <gglessner@gmail.com>
License: GNU GPL

Collects TLS certificates from a host:port and creates a truststore file.
Performs DNS lookup to get canonical hostname, then retrieves certificate chain.

Usage: python cert_collector.py <host> <port>
"""

import sys
import socket
import ssl
import subprocess
import os
import time
from pathlib import Path

def dns_lookup(host):
    """
    Perform DNS lookup to get canonical hostname.
    Returns the canonical hostname or original host if lookup fails.
    """
    try:
        # Try to get canonical name
        canonical_name = socket.getfqdn(host)
        if canonical_name != host:
            print(f"DNS lookup: {host} -> {canonical_name}")
            return canonical_name
        else:
            print(f"DNS lookup: {host} (no CNAME)")
            return host
    except socket.gaierror:
        print(f"DNS lookup failed for {host}, using original hostname")
        return host
    except Exception as e:
        print(f"DNS lookup error for {host}: {e}, using original hostname")
        return host

def collect_certificates_openssl(host, port, hostname):
    """
    Collect certificates using openssl s_client command.
    Returns tuple: (status, message) where status is 'success' or 'error'
    """
    try:
        # Create ca_certs directory if it doesn't exist
        ca_certs_dir = Path('ca_certs')
        ca_certs_dir.mkdir(exist_ok=True)
        
        # Create truststore filename
        truststore_file = ca_certs_dir / f"{host}-truststore.pem"
        
        # Build openssl command
        openssl_cmd = [
            'openssl', 's_client', 
            '-connect', f'{host}:{port}',
            '-servername', hostname,
            '-showcerts'
        ]
        
        # Execute openssl command and capture output
        process = subprocess.Popen(
            openssl_cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        
        # Get the output
        stdout, _ = process.communicate()
        
        if process.returncode != 0:
            return ('error', f'OpenSSL connection failed to {host}:{port}')
        
        # Extract certificates, client CA information, and certificate details from output
        certs = []
        client_cas = []
        cert_subjects = []
        cert_issuers = []
        in_cert = False
        in_client_ca_section = False
        current_cert = []
        
        for line in stdout.split('\n'):
            line = line.strip()
            
            # Extract certificate subject and issuer information
            if line.startswith('subject='):
                cert_subjects.append(line.replace('subject=', ''))
            elif line.startswith('issuer='):
                cert_issuers.append(line.replace('issuer=', ''))
            
            # Extract client CA names
            if 'Acceptable client certificate CA names' in line:
                in_client_ca_section = True
                continue
            elif in_client_ca_section:
                if line.startswith('---') or line == '':
                    in_client_ca_section = False
                elif line.startswith('/'):
                    # Parse distinguished name format
                    client_cas.append(line)
                elif line:
                    client_cas.append(line)
            
            # Extract server certificates
            if line == '-----BEGIN CERTIFICATE-----':
                in_cert = True
                current_cert = [line]
            elif line == '-----END CERTIFICATE-----':
                current_cert.append(line)
                certs.append('\n'.join(current_cert))
                in_cert = False
                current_cert = []
            elif in_cert:
                current_cert.append(line)
        
        if not certs:
            return ('error', f'No certificates found for {host}:{port}')
        
        # Write certificates to truststore file
        with open(truststore_file, 'w') as f:
            for cert in certs:
                f.write(cert + '\n\n')
        
        # Create result message and collect certificate details
        result_msg = f'Collected {len(certs)} certificates to {truststore_file}'
        
        # Create truststore info file
        truststore_info_file = ca_certs_dir / f"{host}-truststore.txt"
        cert_details_list = []
        
        # Extract certificate details from each certificate in the chain
        if certs:
            result_msg += f'\nCertificate chain details:'
            for i, cert in enumerate(certs, 1):
                try:
                    # Extract subject and issuer from certificate using openssl
                    import tempfile
                    import os
                    
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as temp_cert:
                        temp_cert.write(cert)
                        temp_cert_path = temp_cert.name
                    
                    # Get certificate details
                    cert_details_cmd = ['openssl', 'x509', '-in', temp_cert_path, '-noout', '-subject', '-issuer']
                    cert_details_process = subprocess.run(cert_details_cmd, capture_output=True, text=True)
                    
                    os.unlink(temp_cert_path)  # Clean up temp file
                    
                    if cert_details_process.returncode == 0:
                        lines = cert_details_process.stdout.strip().split('\n')
                        subject = ''
                        issuer = ''
                        
                        for line in lines:
                            if line.startswith('subject='):
                                subject = line.replace('subject=', '')
                            elif line.startswith('issuer='):
                                issuer = line.replace('issuer=', '')
                        
                        result_msg += f'\n  Certificate {i}:'
                        if subject:
                            result_msg += f'\n    Subject: {subject}'
                        if issuer:
                            result_msg += f'\n    Issuer: {issuer}'
                        
                        # Collect details for info file
                        cert_details_list.append({
                            'cert_num': i,
                            'subject': subject,
                            'issuer': issuer
                        })
                    else:
                        result_msg += f'\n  Certificate {i}: Unable to parse details'
                        
                except Exception as e:
                    result_msg += f'\n  Certificate {i}: Error parsing - {str(e)}'
            
            # Write certificate details to info file
            with open(truststore_info_file, 'w') as f:
                f.write(f"Certificate Chain Analysis for {host}:{port}\n")
                f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 50 + "\n\n")
                
                for cert_info in cert_details_list:
                    f.write(f"Certificate {cert_info['cert_num']}:\n")
                    f.write(f"  Subject: {cert_info['subject']}\n")
                    f.write(f"  Issuer: {cert_info['issuer']}\n\n")
                
                if client_cas:
                    f.write("Client Certificate CA Names Required:\n")
                    for ca in client_cas:
                        f.write(f"  - {ca}\n")
                else:
                    f.write("No client certificate authentication required\n")
            
            result_msg += f'\nCertificate details saved to {truststore_info_file}'
        
        # Add client CA information if found
        if client_cas:
            result_msg += f'\nClient certificate CA names required:'
            for ca in client_cas:
                result_msg += f'\n  - {ca}'
        else:
            result_msg += '\nNo client certificate authentication required'
        
        return ('success', result_msg)
        
    except FileNotFoundError:
        return ('error', 'OpenSSL not found - please install OpenSSL')
    except Exception as e:
        return ('error', f'Certificate collection failed: {str(e)}')

def collect_certificates_python(host, port, hostname):
    """
    Fallback method using Python's SSL module to collect certificates.
    Returns tuple: (status, message) where status is 'success' or 'error'
    """
    try:
        # Create ca_certs directory if it doesn't exist
        ca_certs_dir = Path('ca_certs')
        ca_certs_dir.mkdir(exist_ok=True)
        
        # Create truststore filename
        truststore_file = ca_certs_dir / f"{host}-truststore.pem"
        
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Connect and get certificate
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)
            sock.connect((host, port))
            
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                
                if not cert_der:
                    return ('error', f'No certificate received from {host}:{port}')
                
                # Convert DER to PEM format
                import base64
                cert_pem = base64.b64encode(cert_der).decode('ascii')
                
                # Format as PEM
                pem_lines = []
                pem_lines.append('-----BEGIN CERTIFICATE-----')
                for i in range(0, len(cert_pem), 64):
                    pem_lines.append(cert_pem[i:i+64])
                pem_lines.append('-----END CERTIFICATE-----')
                
                # Write certificate to truststore file
                with open(truststore_file, 'w') as f:
                    f.write('\n'.join(pem_lines) + '\n')
        
        return ('success', f'Collected certificate to {truststore_file}\nNote: Client CA information not available with Python method - use OpenSSL for full details')
        
    except Exception as e:
        return ('error', f'Python certificate collection failed: {str(e)}')

def main():
    if len(sys.argv) != 3:
        print("Usage: python cert_collector.py <host> <port>", file=sys.stderr)
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
    
    # Perform DNS lookup
    hostname = dns_lookup(host)
    
    # Try openssl first, fallback to Python
    status, message = collect_certificates_openssl(host, port, hostname)
    
    if status == 'error' and 'OpenSSL not found' in message:
        print("OpenSSL not available, trying Python method...", file=sys.stderr)
        status, message = collect_certificates_python(host, port, hostname)
    
    # Print the result
    print(message)
    
    # Return appropriate exit code
    if status == 'success':
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
