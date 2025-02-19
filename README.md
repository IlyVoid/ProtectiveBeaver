# Protective Beaver

---

Protective Beaver is a comprehensive security script designed to harden your Arch Linux system. It automates security checks, vulnerability scans, and system hardening tasks with minimal user interaction.

This script will:

- Verify installation of security tools (ClamAV, rkhunter, fail2ban)
- Perform malware scans and rootkit detection
- Analyze system configurations and network exposure
- Implement security best practices with user consent
- Generate structured audit logs for future review

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Log File Structure](#log-file-structure) 
- [Setting Up Reminders](#setting-up-reminders)
- [Script Overview](#script-overview)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## Features

### Security Hardening
- **Firewall Management**: Automatically enable UFW & close risky ports (22/23/3306)
- **Service Hardening**: Detect and disable unnecessary services (bluetooth/cups)
- **Access Control**: 
  - Fix insecure file permissions (777/666)
  - Verify AppArmor status (Arch Linux compatible)
  - Audit password policies

### Threat Detection
- **Malware Scanning**: Full-system scan with ClamAV
- **Rootkit Detection**: rkhunter system inspection
- **Network Analysis**: Identify suspicious open ports
- **SSH Audit**: Check for password authentication risks

### Maintenance Automation
- Update availability checks
- Cron-based reminder system
- Auditd service activation
- Structured logging of all actions

---

## Installation

### Step 1: Install Dependencies
```bash
sudo pacman -S clamav rkhunter fail2ban ufw audit python python-pip
```

### Step 2: Install Python Requirements
```bash
pip install rich
```

### Step 3: Download & Configure
```bash
git clone https://github.com/yourusername/ProtectiveBeaver.git
cd ProtectiveBeaver
chmod +x PB.py
```

### Usage

Run with elevated privileges:
```bash
sudo ./PB.py
```

Typical Workflow:

    Tool verification check

    Firewall status assessment

    Full malware scan

    Network port analysis

    Security update check

    SSH configuration audit

    File permission review

    Rootkit detection scan

    Service cleanup

    Security framework check

    Password policy audit

    Reminder setup

Interactive Features:

    Port closure confirmation

    Permission repair prompts

    Service disablement requests

    Automatic firewall activation

    Cron job scheduling

Log File Structure

Logs are stored in security_script.log with clear sectioning:
```log

2023-10-10 12:00:00 - INFO - 
==================================================
CHECKING REQUIRED TOOLS
==================================================
2023-10-10 12:00:01 - INFO - All required security tools are installed.

==================================================
CHECKING OPEN PORTS  
==================================================
2023-10-10 12:00:15 - WARNING - Suspicious open port found: tcp LISTEN 0 128 0.0.0.0:22
2023-10-10 12:00:20 - INFO - Port 22 has been closed.
```

## Setting Up Reminders

The script can configure automatic scans via cron:

    Weekly: Every Sunday at midnight

    Monthly: First day of month at midnight

To modify reminders:
```bash
crontab -e
```

# Script Overview
## Core Functions
    ------------------------------------------------------------------------|
    Function	              |    Purpose                              |
    check_tools()	              |    Verify security tool installation    |
    check_firewall()	      |    Configure UFW firewall               |
    scan_files()	              |    Conduct ClamAV malware scan          |
    check_open_ports()	      |    identify/close risky ports           |
    check_ssh_security()	      |    Audit SSH configurations             |
    check_rootkits()	      |    Perform rkhunter scan                |
    enable_auditd()	              |    Activate system auditing             |
    Interactive Modules           |                                         |      
    Function Action               |                                         |
    check_unnecessary_services()  |	   Disable vulnerable services          |
    check_selinux_apparmor()      |    Check MAC frameworks                 |
    check_password_policy()	      |    Verify password requirements         |
    ------------------------------------------------------------------------|

Common Issues:

    Missing sestatus: Expected on Arch Linux - SELinux not used

    UFW Rule Conflicts: Check existing rules with sudo ufw status

    AppArmor Not Found: Install with sudo pacman -S apparmor

Debugging Tips:
```bash
tail -f security_script.log  # Monitor real-time logs
sudo ufw reload               # Force firewall refresh
aa-status                     # Check AppArmor status
```

# Contributing

We welcome security enhancements and Arch Linux improvements!
Guidelines:

    Fork repository

    Create feature branch

    Submit pull request with:

        Code changes

        Updated documentation

        Test cases
