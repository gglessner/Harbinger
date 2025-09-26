# Harbinger - Network Host Monitoring Tool

**Author:** Garland Glessner <gglessner@gmail.com>  
**License:** GNU GPL  
**Version:** 1.0

## Overview

Harbinger is a Python3 network monitoring tool designed to detect new hosts with specific open TCP ports on your network. It uses SQLite3 databases to track host discovery history and sends email reports when new hosts are detected.

## Features

- **Multi-port monitoring**: Monitor multiple TCP ports simultaneously
- **Flexible scanning**: Support for custom shell commands or nmap scans
- **Email reporting**: Automatic email notifications for new host discoveries
- **Database tracking**: SQLite3 database with separate tables per port
- **Dual operation modes**: Cron mode for scheduled runs or standalone mode for continuous operation
- **Comprehensive logging**: Detailed logging for troubleshooting
- **Batch reporting**: Groups reports by email address to avoid spam

## Requirements

- Python 3.6+
- Required Python packages:
  - PyYAML
  - schedule
- System tools:
  - nmap (for nmap scanning) - optional, custom commands can be used instead
  - SQLite3 (included with Python)

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
3. Install nmap (if using nmap scanning):
   ```bash
   # Ubuntu/Debian
   sudo apt-get install nmap
   
   # CentOS/RHEL
   sudo yum install nmap
   
   # Windows (using Chocolatey)
   choco install nmap
   
   # macOS (using Homebrew)
   brew install nmap
   ```
4. Make harbinger.py executable (Unix/Linux/macOS):
   ```bash
   chmod +x harbinger.py
   ```

## Configuration

Edit `harbinger.yaml` to configure your monitoring setup:

### Email Configuration
```yaml
email:
  smtp_server: "smtp.gmail.com"
  smtp_port: 587
  use_tls: true
  username: "your-email@gmail.com"
  password: "your-app-password"
  from_address: "your-email@gmail.com"
```

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
  email: "security@company.com"
  nmap_scan: "nmap -p {port} --open 192.168.1.0/24"

port_https:
  port: 443
  email: "security@company.com"
  nmap_scan: "nmap -p {port} --open --max-retries 2 192.168.1.0/24"

port_custom:
  port: 8080
  email: "devops@company.com"
  command: "python custom_scanner.py --port 8080 --subnet 192.168.1.0/24"
```

**Configuration Options:**
- `port`: TCP port number to monitor
- `email`: Email address to receive reports
- `command`: Custom shell command that outputs IP addresses (one per line) - supports `{port}` placeholder
- `nmap_scan`: Full nmap command with `{port}` placeholder for flexible scanning options

**Port Placeholder:**
Both `command` and `nmap_scan` fields support the `{port}` placeholder, which gets replaced with the actual port number:
- `nmap -p {port} --open 192.168.1.0/24` - Basic port scan
- `nmap -p {port} --open --max-retries 2 192.168.1.0/24` - With retry limit
- `nmap -p {port} --open -T4 192.168.1.0/24` - With timing template
- `python custom_scanner.py --port {port} --subnet 192.168.1.0/24` - Custom script with port

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

## Email Reports

Harbinger generates comprehensive reports for all configured email addresses, ensuring complete monitoring visibility:

**Report Types:**
- **New Hosts Detected**: When new hosts are found on monitored ports
- **Scan Failures**: When commands fail or scripts are missing
- **No New Hosts**: When scans complete successfully but find no new hosts
- **Mixed Results**: When some ports have new hosts and others have failures

**Report Content:**
- Total count of new hosts detected
- Total count of scan failures
- Detailed breakdown by port showing:
  - New hosts found (with post-command output if configured)
  - `[SCAN FAILED: error message]` for failed scans
  - `"No new hosts detected"` for successful scans with no new hosts
- Timestamp of report generation

**Report Subjects:**
- `"Harbinger Report: X new host(s) detected"` - New hosts found
- `"Harbinger Report: Scan failures detected"` - Command/script failures
- `"Harbinger Report: X new hosts detected, Y scan failures"` - Mixed results
- `"Harbinger Report: No new hosts detected"` - All scans successful, no new hosts

**Always-On Reporting**: Reports are sent to all configured email addresses regardless of scan results, ensuring you always know the monitoring system is operational.

## Report Files

When `save_to_file: true` is enabled in the configuration, Harbinger will save timestamped report files in addition to sending emails. This is useful for:
- Local backup of reports
- Integration with other monitoring systems
- Manual review and analysis
- Compliance and audit trails

**File Format:**
- Filename: `[username]_[timestamp].txt`
- Location: `reports/` directory (configurable)
- Content: Full report details including headers and metadata

**Example filenames:**
- `security_20240925_143022.txt`
- `admin_20240925_143022.txt`
- `devops_20240925_143022.txt`

## Logging

Harbinger creates detailed logs in `harbinger.log` (configurable) with:
- Scan execution details
- New host discoveries
- Email delivery status
- Error messages and debugging information

Log levels: DEBUG, INFO, WARNING, ERROR

## Examples

### Basic SSH Monitoring
```yaml
port_ssh:
  port: 22
  email: "admin@company.com"
  nmap_scan: "nmap -p {port} --open 192.168.1.0/24"
```

### Custom Command Monitoring
```yaml
port_custom:
  port: 8080
  email: "devops@company.com"
  command: "/usr/local/bin/custom_scanner.sh --port {port} --subnet 10.0.0.0/8"
```

### Multiple Email Addresses
```yaml
port_ssh:
  port: 22
  email: "security@company.com"
  nmap_scan: "nmap -p {port} --open 192.168.1.0/24"

port_rdp:
  port: 3389
  email: "admin@company.com"
  nmap_scan: "nmap -p {port} --open 192.168.1.0/24"
```

This configuration will send separate reports to different email addresses.

### Report Examples

**Example 1: New Hosts Detected**
```
Subject: Harbinger Report: 3 new hosts detected

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
Subject: Harbinger Report: Scan failures detected

New hosts detected: 0
Scan failures: 1

Details:

Port 8080 (Custom Service):
[SCAN FAILED: Command failed with return code 2: python custom_scanner.py --subnet 10.0.0.0/24 --port 8080 - python: can't open file 'custom_scanner.py': [Errno 2] No such file or directory]
```

**Example 3: Mixed Results**
```
Subject: Harbinger Report: 2 new hosts detected, 1 scan failures

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
3. **Email configuration**: Test SMTP settings with a simple email test
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
