# Harbinger - Network Host Monitoring Tool

**Author:** Garland Glessner <gglessner@gmail.com>  
**License:** GNU GPL  
**Version:** 1.0

## Overview

Harbinger is a Python3 network monitoring tool designed to detect new hosts with specific open TCP ports on your network. It uses SQLite3 databases to track host discovery history and sends email reports when new hosts are detected.

## Features

- **Multi-port monitoring**: Monitor multiple TCP ports simultaneously
- **Label-based grouping**: Group ports by custom labels for organized reporting
- **Flexible scanning**: Support for custom shell commands or nmap scans
- **Email reporting**: Automatic email notifications via SMTP or local mail command
- **Report-only mode**: Generate local reports without sending emails
- **Database tracking**: SQLite3 database with separate tables per port
- **Dual operation modes**: Cron mode for scheduled runs or standalone mode for continuous operation
- **Comprehensive logging**: Detailed logging for troubleshooting
- **Smart reporting**: Groups reports by label+email combination for organized alerts

## Requirements

- Python 3.6+
- Required Python packages:
  - PyYAML
  - schedule
- System tools:
  - nmap (for nmap scanning) - optional, custom commands can be used instead
  - openssl (for TLS/SSL certificate operations) - required for TLS checking and certificate collection
  - SQLite3 (included with Python)
- Optional Python packages for advanced features:
  - confluent-kafka (for Kafka security testing)

## Supported Operating Systems

- **Windows** (Windows 10/11, Windows Server)
- **Linux** (Ubuntu, CentOS, RHEL, Debian, etc.)
- **macOS** (10.14+)
- **Unix-like systems** (FreeBSD, OpenBSD, etc.)

## Installation

1. Clone or download the Harbinger files
2. Install required Python packages:
   ```bash
   pip3 install pyyaml schedule
   ```
3. Install system dependencies:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install nmap openssl mailutils  # mailutils for local mail support
   
   # CentOS/RHEL
   sudo yum install nmap openssl mailx  # mailx for local mail support
   
   # Windows (using Chocolatey)
   choco install nmap openssl
   
   # macOS (using Homebrew)
   brew install nmap openssl
   ```

**Note:** For local mail support on Unix/Linux systems, install `mailutils` (Debian/Ubuntu) or `mailx` (CentOS/RHEL). Windows users should use SMTP configuration.

4. Install optional Python packages for advanced features:
   ```bash
   # For Kafka security testing
   pip3 install confluent-kafka
   ```

5. Make harbinger.py executable (Unix/Linux/macOS):
   ```bash
   chmod +x harbinger.py
   ```

## Configuration

Edit `harbinger.yaml` to configure your monitoring setup:

### Email Configuration

Harbinger supports two email delivery methods:

**Option 1: SMTP Configuration** (for external email services like Gmail, Office 365, etc.)
```yaml
email:
  smtp_server: "smtp.gmail.com"
  smtp_port: 587
  use_tls: true
  username: "your-email@gmail.com"
  password: "your-app-password"
  from_address: "your-email@gmail.com"
```

**Option 2: Local Mail Configuration** (for Unix/Linux systems using the `mail` command)
```yaml
email:
  use_local_mail: true
  mail_command: "mail"  # or "/usr/bin/mail" for full path
```

**Notes:**
- Local mail configuration uses the system `mail` command (similar to `mail -s "subject" recipient`)
- Requires the `mail` command to be installed and configured on your system
- Works on Unix/Linux systems where local mail delivery is configured
- Not supported on Windows (use SMTP instead)

### Report Configuration
```yaml
reports:
  save_to_file: true  # Save reports to timestamped files
  directory: "reports"  # Directory for report files
```

### Port Monitoring Sections
Each port to monitor requires a `port_*` section:

```yaml
port_ssh:
  port: 22
  label: "Network Security"          # Groups ports for reporting
  port_label: "SSH"                # Display label in reports
  email: "security@company.com"
  nmap_scan: "nmap -p {port} --open 192.168.1.0/24"

port_https:
  port: 443
  label: "Network Security"         # Same label = same report group
  port_label: "HTTPS"
  email: "security@company.com"
  nmap_scan: "nmap -p {port} --open --max-retries 2 192.168.1.0/24"

port_custom:
  port: 8080
  label: "Development"              # Different label = separate report
  port_label: "Custom Service"
  email: "devops@company.com"
  command: "python custom_scanner.py --port {port} --subnet 192.168.1.0/24"
```

**Configuration Options:**
- `port`: TCP port number to monitor
- `label`: **Required** - Groups ports for reporting (used in email subjects and filenames)
- `port_label`: **Optional** - Display label for this port in report content
- `email`: **Optional** - Email address to receive reports (omit for report-only mode)
- `command`: Custom shell command that outputs IP addresses (one per line) - supports `{port}` placeholder
- `nmap_scan`: Full nmap command with `{port}` placeholder for flexible scanning options
- `post_command`: **Optional** - Command to run for each detected host - supports `{host}` and `{port}` placeholders

**Port Placeholder:**
Both `command` and `nmap_scan` fields support the `{port}` placeholder, which gets replaced with the actual port number:
- `nmap -p {port} --open 192.168.1.0/24` - Basic port scan
- `nmap -p {port} --open --max-retries 2 192.168.1.0/24` - With retry limit
- `nmap -p {port} --open -T4 192.168.1.0/24` - With timing template
- `python custom_scanner.py --port {port} --subnet 192.168.1.0/24` - Custom script with port

**Post-Command Placeholders:**
The `post_command` field supports both `{host}` and `{port}` placeholders:
- `nmap -sV -p {port} {host}` - Service version scan
- `curl -I http://{host}` - HTTP header check
- `python post_command/kafka.py {host}:{port}` - Custom security scanner

**Optimized Post-Command Examples:**
For efficient scanning, use command chaining with `&&` and `||` operators:

- **Basic port check with service detection:**
  ```yaml
  post_command: "python post_command/port_check.py {host} {port} && nmap -sV -p {port} {host}"
  ```

- **HTTP with TLS detection:**
  ```yaml
  post_command: "python post_command/port_check.py {host} {port} && (python post_command/tls_check.py {host} {port} && curl -k -I https://{host} || curl -I http://{host})"
  ```

- **Kafka with intelligent TLS detection:**
  ```yaml
  post_command: "python post_command/port_check.py {host} {port} && (python post_command/tls_check.py {host} {port} && python post_command/kafka.py --tls {host} {port} || python post_command/kafka.py {host} {port})"
  ```

- **HTTP GET request with full response:**
  ```yaml
  post_command: "python post_command/port_check.py {host} {port} && python post_command/http_check.py {host} {port}"
  ```

- **HTTPS GET request with TLS verification:**
  ```yaml
  post_command: "python post_command/port_check.py {host} {port} && python post_command/tls_check.py {host} {port} && python post_command/http_check.py {host} {port} https"
  ```

**Command Chaining Logic:**
- `command1 && command2` - Run command2 only if command1 succeeds
- `command1 || command2` - Run command2 only if command1 fails
- `(command1 && command2) || command3` - Try command1 and command2, fallback to command3 if either fails

## Usage

### Cron Mode (Single Run)
For scheduled execution via cron:

```bash
./harbinger.py --mode cron
```

Example cron entry for daily runs at 8:00 AM:
```bash
0 8 * * * /path/to/harbinger.py --mode cron
```

### Standalone Mode (Continuous Operation)
For continuous operation with scheduled reports:

```bash
./harbinger.py --mode standalone
```

The standalone mode will run continuously and generate reports at the time specified in the config file (`standalone.report_time`).

### Custom Configuration File
```bash
./harbinger.py --config /path/to/custom.yaml --mode cron
```

## Database Structure

Harbinger creates a SQLite database (`harbinger.db`) with separate tables for each monitored port:

```sql
CREATE TABLE hosts_port_22 (
    ip_address TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
```

## Report Generation

Harbinger uses **label-based grouping** to organize reports intelligently:

### Grouping Logic
- **First**: Group by `label` field
- **Second**: Within each label, sub-group by `email` address
- **Missing email**: Creates report-only files (no email sent)
- **Same label + same email**: Single combined report
- **Same label + different emails**: Separate reports per email

### Report Types
- **New Hosts Detected**: When new hosts are found on monitored ports
- **Scan Failures**: When commands fail or scripts are missing
- **No New Hosts**: When scans complete successfully but find no new hosts
- **Mixed Results**: When some ports have new hosts and others have failures

### Report Content
- Total count of new hosts detected
- Total count of scan failures
- Detailed breakdown by port showing:
  - Port number and `port_label` (if configured)
  - New hosts found (with post-command output if configured)
  - `[SCAN FAILED: error message]` for failed scans
  - `"No new hosts detected"` for successful scans with no new hosts
- Timestamp of report generation

### Report Subjects
- `"Harbinger Report for [LABEL]: X new host(s) detected"` - New hosts found
- `"Harbinger Report for [LABEL]: Scan failures detected"` - Command/script failures
- `"Harbinger Report for [LABEL]: X new hosts detected, Y scan failures"` - Mixed results
- `"Harbinger Report for [LABEL]: No new hosts detected"` - All scans successful, no new hosts

### Always-On Reporting
Reports are generated for all configured groups regardless of scan results, ensuring you always know the monitoring system is operational.

## Report Files

When `save_to_file: true` is enabled in the configuration, Harbinger will save timestamped report files in addition to sending emails. This is useful for:
- Local backup of reports
- Integration with other monitoring systems
- Manual review and analysis
- Compliance and audit trails

**File Format:**
- Filename: `[LABEL]_[timestamp].txt` (spaces converted to underscores)
- Location: `reports/` directory (configurable)
- Content: Full report details including headers and metadata

**Example filenames:**
- `Network_Security_20240925_143022.txt`
- `Admin_Services_20240925_143022.txt`
- `Development_20240925_143022.txt`
- `Internal_Monitoring_20240925_143022.txt` (report-only)

## Logging

Harbinger creates detailed logs in `harbinger.log` (configurable) with:
- Scan execution details
- New host discoveries
- Email delivery status
- Error messages and debugging information

Log levels: DEBUG, INFO, WARNING, ERROR

## Examples

### Optimized Scanning Strategy

Harbinger includes intelligent post-command scripts that optimize scanning performance:

1. **port_check.py** - Fast port connectivity verification
2. **tls_check.py** - TLS/SSL capability detection  
3. **kafka.py** - Kafka security testing with TLS support and smart error detection
4. **http_check.py** - HTTP GET requests with full response capture
5. **cert_collector.py** - TLS certificate collection and truststore creation

**Optimization Benefits:**
- **Speed**: Skip expensive operations when ports are closed
- **Intelligence**: Choose appropriate scanning methods based on TLS detection
- **Efficiency**: Avoid redundant checks and timeouts
- **Reliability**: Graceful fallbacks when services aren't available
- **Smart Error Detection**: Distinguish between service failures and protocol mismatches
- **Certificate Management**: Automatic collection and storage of TLS certificates with cross-platform deduplication

**Kafka Security Scanner Features:**
- **TLS Support**: Use `--tls` flag for TLS-only testing
- **Certificate Integration**: Automatically uses collected certificates for self-signed servers
- **Port-Specific Certificates**: Uses `ca_certs/{host}-{port}.pem` format for proper certificate management
- **Intelligent Error Messages**: 
  - "Not a Kafka service" for protocol mismatches
  - "Connection refused - service not running" for connection failures
  - "TLS connection failed - [specific error]" for SSL issues
  - "Authentication failed" for auth-related errors

**Smart Chain Wrapper Script:**
- **kafka.sh** (Linux/macOS): Complete chain with always-success return code
- **Benefits**: Captures all logs while treating expected failures as success

**Certificate Collection Features:**
- **Cross-Platform Storage**: Linux/macOS uses deduplication with symlinks, Windows uses normal files
- **Port-Specific Filenames**: Prevents collisions between different ports on the same host
- **Automatic Integration**: Other scripts automatically find and use the correct certificate files
- **Detailed Analysis**: Generates human-readable certificate chain analysis files

### Basic SSH Monitoring
```yaml
port_ssh:
  port: 22
  label: "Network Security"
  port_label: "SSH"
  email: "admin@company.com"
  nmap_scan: "nmap -p {port} --open 192.168.1.0/24"
  post_command: "python post_command/port_check.py {host} {port} && nmap -sV -p {port} {host}"
```

### HTTP Service with TLS Detection
```yaml
port_web:
  port: 80
  label: "Web Services"
  port_label: "HTTP"
  email: "security@company.com"
  nmap_scan: "nmap -p {port} --open 192.168.1.0/24"
  post_command: "python post_command/port_check.py {host} {port} && (python post_command/tls_check.py {host} {port} && curl -k -I https://{host} || curl -I http://{host})"
```

### Intelligent Kafka Security Scanning
```yaml
port_kafka:
  port: 9092
  label: "Data Services"
  port_label: "Kafka"
  email: "security@company.com"
  nmap_scan: "nmap -p {port} --open 192.168.1.0/24"
  post_command: "python post_command/port_check.py {host} {port} && (python post_command/tls_check.py {host} {port} && python post_command/kafka.py --tls {host} {port} || python post_command/kafka.py {host} {port})"
```

### Smart Chain Wrapper (Recommended for Linux/macOS)
```yaml
port_kafka_smart:
  port: 9092
  label: "Data Services"
  port_label: "Kafka Smart Chain"
  email: "security@company.com"
  nmap_scan: "nmap -p {port} --open 192.168.1.0/24"
  post_command: "post_command/kafka.sh {host} {port}"
```

### TLS Certificate Collection and Validation
```yaml
port_https_cert:
  port: 443
  label: "Certificate Management"
  port_label: "HTTPS with Cert Collection"
  email: "security@company.com"
  nmap_scan: "nmap -p {port} --open 192.168.1.0/24"
  post_command: "python post_command/port_check.py {host} {port} && python post_command/tls_check.py {host} {port} && python post_command/cert_collector.py {host} {port} && python post_command/kafka.py --tls {host} {port}"
```

**Certificate Collection Output:**
- Creates `ca_certs/{host}-{port}.pem` with the certificate chain
- Creates `ca_certs/{host}-{port}.txt` with detailed certificate analysis
- On Linux/macOS: Automatically deduplicates identical certificates using SHA256 hashes
- On Windows: Creates normal files for maximum compatibility

**Certificate Collection Workflow:**
1. **Collect Certificates**: `cert_collector.py` retrieves the full certificate chain
2. **Create Certificate Files**: Saves certificates to `ca_certs/{host}-{port}.pem` (port-specific filenames)
3. **Generate Analysis**: Creates `ca_certs/{host}-{port}.txt` with detailed certificate information
4. **Auto-Validation**: Other scripts automatically use the certificate files for self-signed certificates
5. **Cross-Platform Deduplication**: 
   - **Linux/macOS**: Uses SHA256 hash-based deduplication with symlinks for space efficiency
   - **Windows**: Creates normal files for maximum compatibility

**Certificate File Format:**
- **Filename**: `ca_certs/{host}-{port}.pem` (e.g., `ca_certs/10.0.0.1-443.pem`)
- **Benefits**: No filename collisions between different ports on the same host
- **Integration**: `kafka.py` automatically finds and uses the correct certificate file

### HTTP Service with Full Response Capture
```yaml
port_http:
  port: 80
  label: "Web Services"
  port_label: "HTTP"
  email: "security@company.com"
  nmap_scan: "nmap -p {port} --open 192.168.1.0/24"
  post_command: "python post_command/port_check.py {host} {port} && python post_command/http_check.py {host} {port}"
```

### HTTPS Service with TLS Verification
```yaml
port_https:
  port: 443
  label: "Web Services"
  port_label: "HTTPS"
  email: "security@company.com"
  nmap_scan: "nmap -p {port} --open 192.168.1.0/24"
  post_command: "python post_command/port_check.py {host} {port} && python post_command/tls_check.py {host} {port} && python post_command/http_check.py {host} {port} https"
```

### Custom Web Application Testing
```yaml
port_webapp:
  port: 8080
  label: "Development"
  port_label: "Web App"
  email: "devops@company.com"
  nmap_scan: "nmap -p {port} --open 192.168.1.0/24"
  post_command: "python post_command/port_check.py {host} {port} && python post_command/http_check.py {host} {port} http /api/status"
```

### Custom Command Monitoring
```yaml
port_custom:
  port: 8080
  label: "Development"
  port_label: "Custom Service"
  email: "devops@company.com"
  command: "/usr/local/bin/custom_scanner.sh --port {port} --subnet 10.0.0.0/8"
```

### Label-Based Grouping Examples

**Example 1: Multiple Ports, Same Group**
```yaml
port_ssh:
  port: 22
  label: "Network Security"
  port_label: "SSH"
  email: "security@company.com"
  nmap_scan: "nmap -p {port} --open 192.168.1.0/24"

port_https:
  port: 443
  label: "Network Security"        # Same label
  port_label: "HTTPS"
  email: "security@company.com"    # Same email
  nmap_scan: "nmap -p {port} --open 192.168.1.0/24"
```
*Result: One combined report sent to security@company.com*

**Example 2: Same Label, Different Emails**
```yaml
port_ssh:
  port: 22
  label: "Network Security"
  port_label: "SSH"
  email: "security@company.com"
  nmap_scan: "nmap -p {port} --open 192.168.1.0/24"

port_rdp:
  port: 3389
  label: "Network Security"        # Same label
  port_label: "RDP"
  email: "admin@company.com"       # Different email
  nmap_scan: "nmap -p {port} --open 192.168.1.0/24"
```
*Result: Two separate reports - one to each email address*

**Example 3: Report-Only Mode**
```yaml
port_dns:
  port: 53
  label: "Internal Monitoring"
  port_label: "DNS"
  # No email field = report-only mode
  nmap_scan: "nmap -p {port} --open 192.168.1.0/24"
```
*Result: Generates report file only, no email sent*

### Report Examples

**Example 1: New Hosts Detected**
```
Subject: Harbinger Report for Network Security: 3 new hosts detected

New hosts detected: 3
Scan failures: 0

Details:

Port 22 (SSH):
10.0.0.100
10.0.0.101

Port 80 (HTTP):
10.0.0.102
```

**Example 2: Scan Failures**
```
Subject: Harbinger Report for Development: Scan failures detected

New hosts detected: 0
Scan failures: 1

Details:

Port 8080 (Custom Service):
[SCAN FAILED: Command failed with return code 2: python custom_scanner.py --subnet 10.0.0.0/24 --port 8080 - python: can't open file 'custom_scanner.py': [Errno 2] No such file or directory]
```

**Example 3: Mixed Results**
```
Subject: Harbinger Report for Network Security: 2 new hosts detected, 1 scan failures

New hosts detected: 2
Scan failures: 1

Details:

Port 22 (SSH):
10.0.0.100
10.0.0.101

Port 443 (HTTPS):
No new hosts detected.

Port 8080 (Custom Service):
[SCAN FAILED: Command failed with return code 127: custom_script.sh: command not found]
```

## Troubleshooting

1. **Check logs**: Review `harbinger.log` for error messages
2. **Test commands**: Verify your scan commands work manually
3. **Email configuration**: 
   - **SMTP**: Test SMTP settings with a simple email test
   - **Local mail**: Test with `echo "test" | mail -s "test" your-email@domain.com`
4. **Permissions**: Ensure harbinger.py has execute permissions (Unix/Linux/macOS)
5. **Network access**: Verify the monitoring system can reach target networks

### Scan Failure Troubleshooting

When reports show `[SCAN FAILED: ...]` errors:

**Command Not Found:**
- Verify the command exists and is in your PATH
- Use full paths for custom scripts: `/full/path/to/script.sh`
- Check file permissions on custom scripts

**Permission Issues:**
- Ensure the user running Harbinger has permission to execute commands
- Some nmap scans may require elevated privileges
- Check firewall rules that might block outgoing scans

**Script Errors:**
- Test custom scripts manually before configuring them
- Verify script dependencies are installed
- Check script syntax and error handling

**Network Issues:**
- Verify network connectivity to target subnets
- Check if target networks are accessible from monitoring host
- Test basic connectivity: `ping`, `telnet`, or `nc` to target hosts

### Post-Command Script Troubleshooting

**Kafka Scanner Issues:**
- **"Not a Kafka service"**: Service is running but not Kafka - this is normal for non-Kafka ports
- **"TLS connection failed"**: Check if the service requires TLS or if certificates are valid
- **"Connection refused"**: Service is not running on the target port
- **Truststore errors**: Run `cert_collector.py` first to collect valid certificates

**Certificate Collection Issues:**
- **OpenSSL errors**: Ensure OpenSSL is installed and accessible
- **DNS resolution**: Verify hostname resolution works: `nslookup <hostname>`
- **Certificate parsing**: Check `ca_certs/{host}-{port}.txt` for detailed certificate information
- **Permission errors**: Ensure write access to the `ca_certs/` directory
- **Windows symlinks**: On Windows, certificate files are created normally (no symlinks needed)
- **Linux/macOS deduplication**: Duplicate certificates are automatically deduplicated using SHA256 hashes

**Port Check Issues:**
- **Timeout errors**: Network latency or firewall blocking - increase timeout if needed
- **Connection refused**: Port is closed or service not running
- **Nmap failures**: Script falls back to basic socket connection automatically

**TLS Check Issues:**
- **"TLS not detected"**: Service doesn't support TLS/SSL encryption
- **Certificate errors**: Service has invalid or self-signed certificates (normal for self-signed certs)
- **Timeout errors**: Service is slow to respond or network issues
- **Improved detection**: Script now correctly identifies TLS even with certificate verification issues

### OS-Specific Issues

**Windows:**
- Ensure nmap is in your PATH or use full path in commands
- PowerShell may have execution policy restrictions - use Command Prompt if needed
- Antivirus software may block nmap - add exceptions if necessary

**Linux/Unix:**
- Ensure nmap has proper permissions (may need sudo for some scan types)
- Check firewall rules that might block outgoing scans
- Verify network interface permissions

**macOS:**
- nmap may require Xcode command line tools
- Gatekeeper may block execution - allow in System Preferences if prompted

### Email Delivery Troubleshooting

**SMTP Issues:**
- **Authentication failed**: Verify username and password are correct
- **Connection timeout**: Check firewall rules and SMTP server accessibility
- **TLS errors**: Ensure `use_tls: true` matches your SMTP server configuration
- **Gmail**: Use app-specific passwords instead of regular passwords

**Local Mail Issues:**
- **"mail: command not found"**: Install `mailutils` (Debian/Ubuntu) or `mailx` (CentOS/RHEL)
- **"Cannot send message"**: Ensure local mail delivery is configured on your system
- **Mail not delivered**: Check mail logs with `sudo tail -f /var/log/mail.log`
- **Permission denied**: Ensure the `mail` command has proper permissions
- **Testing**: Test local mail delivery with `echo "test" | mail -s "test" user@localhost`

**Cross-Platform Considerations:**
- **Windows**: Use SMTP configuration (local mail not available)
- **Unix/Linux**: Both SMTP and local mail options are supported
- **macOS**: Both SMTP and local mail options are supported

## Certificate Management and Storage

### Cross-Platform Certificate Storage

Harbinger includes an intelligent certificate storage system that adapts to your operating system:

**Linux/macOS (Space-Efficient Mode):**
- Uses SHA256 hash-based deduplication
- Identical certificates stored only once in `ca_certs/raw_certs/`
- Symlinks used to reference certificates from multiple host:port combinations
- Automatic space savings for environments with duplicate certificates

**Windows (Compatibility Mode):**
- Creates normal certificate files in `ca_certs/{host}-{port}.pem`
- No symlinks or complex file operations
- Maximum compatibility with Windows file systems
- Simple, reliable operation

### Certificate File Structure

```
ca_certs/
├── 10.0.0.1-443.pem          # Certificate file (or symlink on Linux/macOS)
├── 10.0.0.1-443.txt          # Certificate analysis file
├── 10.0.0.17-443.pem         # Certificate file (or symlink on Linux/macOS)
├── 10.0.0.17-443.txt         # Certificate analysis file
└── raw_certs/                # Linux/macOS only - unique certificates by hash
    ├── f5cee1f4...pem        # Actual certificate file (SHA256 hash-based)
    └── 9b9b2250...pem        # Actual certificate file (SHA256 hash-based)
```

### Benefits of Port-Specific Filenames

- **No Collisions**: Same host with different ports (HTTP vs HTTPS) have separate certificate files
- **Port-Specific Configurations**: Each port can have its own TLS configuration
- **Automatic Integration**: `kafka.py` and other scripts automatically find the correct certificate
- **Easy Management**: Clear naming convention makes certificate files easy to identify

## Security Considerations

- Store email passwords securely (consider using app-specific passwords for Gmail)
- Run with minimal required privileges
- Ensure network scanning is authorized on target networks
- Regularly review and rotate credentials
- Consider using dedicated service accounts for email

## License

This program is licensed under the GNU General Public License. See the LICENSE file for details.

## Support

For issues or questions, contact: gglessner@gmail.com
