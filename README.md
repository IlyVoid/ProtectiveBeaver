# Protective Beaver

---

Protective Beaver is a security script designed to help you enhance the security of your Arch Linux system. It automates various tasks like malware scanning, file permission checking, log analysis, firewall status verification, and more.

This script will:

- Check if essential security tools like ClamAV, rkhunter, and fail2ban are installed(if not it'll prompt to install it at that moment).
- Scan your system for malware using ClamAV.
- Check file permissions and allow you to fix any weak permissions.
- Scan system logs for suspicious activity (e.g., brute force attempts).
- Ensure your firewall (UFW) is enabled and provide an option to enable it.
- Set up reminders for periodic security checks via cron.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Setting Up Reminders](#setting-up-reminders)
- [Script Overview](#script-overview)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## Features

- **Security Tool Check**: Verifies if ClamAV, rkhunter, and fail2ban are installed.
- **ClamAV Malware Scan**: Scans your system recursively to check for malware.
- **File Permission Check**: Checks for files with overly permissive access and offers to fix them.
- **Log Analysis**: Scans system logs for suspicious activities like brute-force login attempts or exploits.
- **Firewall Check**: Checks if UFW (Uncomplicated Firewall) is enabled and allows enabling it if not.
- **Reminder Setup**: Allows you to set up weekly or monthly reminders to run the script automatically using cron.

---

## Installation

### Step 1: Install Dependencies

Before running the script, make sure your system has the necessary security tools installed.

1. **Install ClamAV, rkhunter, and fail2ban**: Run the following command to install the required tools:
    ```bash
    sudo pacman -S clamd rkhunter fail2ban ufw
    ```

2. **Install Python 3 and pip (if not already installed)**:
    ```bash
    sudo pacman -S python python-pip
    ```

3. **Install Rich (for beautiful output)**: The script uses the `rich` Python package for beautiful console output. Install it via pip:
    ```bash
    pip install rich
    ```

### Step 2: Download the Script

Clone or download the script to your desired directory. For example:
```bash
git clone https://github.com/yourusername/ProtectiveBeaver.git
cd ProtectiveBeaver
```

Alternatively, if you don't have Git:

    Download the ZIP file from the GitHub repository.
    Extract it to a directory on your system.

### Step 3: Make the Script Executable

After downloading or cloning the script, make it executable:

```bash
chmod +x PB.py
```

### Step 4: Run the Script

To run the script, simply execute it with Python:
```bash
python3 PB.py
```

You may need to run the script with sudo depending on the permissions of the files and directories being scanned:
```bash
sudo python3 PB.py
```

---

## Usage

When you run the script, it will perform several checks and tasks:

- Check for Missing Tools: The script will check if ClamAV, rkhunter, and fail2ban are installed. If any of them are missing, the script will suggest how to install them.

- Run ClamAV Malware Scan: It will perform a system-wide scan for malware using clamscan. You will see a report on any infected files found.

- File Permission Check: It will check the permissions of all files on your system and identify files with weak permissions (e.g., files with 777 or 666 permissions). You will have the option to fix these permissions automatically.

- Log Analysis: The script will check the system logs for any suspicious activity such as failed login attempts, segfaults, and other anomalies.

- Firewall Check: It will check if ufw (Uncomplicated Firewall) is active. If it's not, it will offer to enable it for you.

- Reminder Setup: After running the script, you will have the option to set up a cron job to run the script automatically at regular intervals (weekly or monthly).

### Sample Output:


[bold purple]Protective Beaver[/bold purple]
- Checking for missing security tools...
[green]All required security tools are installed.[/green]
- Running ClamAV scan...
[green]No malware found.[/green]
- Checking file permissions...
[green]No weak file permissions found.[/green]
- Checking logs for suspicious activity...
[red]Suspicious log entry detected:[/red] Failed password for user root from 192.168.1.10
- Checking firewall status...
[green]Firewall enabled.[/green]
- Would you like to set up regular reminders to run this script? (weekly/monthly/n): weekly
[green]Reminder set to run the script at: 0 0 * * 0[/green]


# Setting Up Reminders

The script offers the option to set up regular reminders using cron, which will automatically run the script at specified intervals (weekly or monthly).

When prompted, you can choose between:

    weekly: The script will run every Sunday at midnight.
    monthly: The script will run on the first day of every month at midnight.
    no: No reminders will be set.

To set up the reminder:

    Choose your preferred interval.
    The script will automatically add an entry to your crontab.

If you need to manually edit your cron jobs, you can open your crontab by running:

```bash
crontab -e
```

## Script Overview

The script is divided into several functions:

    check_tools(): Verifies if required tools are installed.
    scan_files(): Runs ClamAV to check for malware on the system.
    check_file_permissions(): Checks for files with weak permissions and offers to fix them.
    check_logs(): Scans system logs for suspicious activity.
    firewall_status(): Checks if UFW is active and offers to enable it.
    enable_reminders(): Prompts the user to set up cron-based reminders.
    setup_reminder(): Adds a cron job to run the script at a specified interval.

The script uses the rich package for colorful and formatted output to make the console output more user-friendly.
Troubleshooting

    Missing Dependencies: If you get errors about missing dependencies, make sure all required packages (clamav, rkhunter, fail2ban, ufw, python3, rich) are installed.

    Permission Issues: Some checks (like scanning files or accessing system logs) require superuser (root) privileges. Run the script with sudo if needed:

```bash
sudo python3 PB.py
```

Firewall Issues: If UFW is not installed or not working, install it using:

    sudo pacman -S ufw

# Contributing

We welcome contributions to improve the script! If you would like to help, please fork the repository, make your changes, and submit a pull request.
