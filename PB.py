import os
import subprocess
import shutil
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
import logging

# Initialize Rich console for pretty output
console = Console()

# Set up logging to track script execution and results
logging.basicConfig(
    filename="security_script.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

def log_section(title):
    """Log a section header for better readability."""
    logging.info(f"\n{'=' * 50}")
    logging.info(f"{title.upper()}")
    logging.info(f"{'=' * 50}")

def install_tools(missing_tools):
    """Install missing security tools."""
    console.print(f"[yellow]Installing missing tools: {', '.join(missing_tools)}[/yellow]")
    try:
        subprocess.run(["sudo", "pacman", "-S", "--noconfirm"] + missing_tools, check=True)
        console.print("[green]Missing tools installed successfully.[/green]")
        logging.info(f"Installed missing tools: {', '.join(missing_tools)}")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error installing tools: {e}[/red]")
        logging.error(f"Error installing tools: {e}")

def check_tools():
    """Check if required security tools are installed."""
    log_section("Checking Required Tools")
    tools = {"ClamAV": "clamscan", "rkhunter": "rkhunter", "fail2ban": "fail2ban-client", "ufw": "ufw", "auditd": "auditctl"}
    missing_tools = []
    
    for name, cmd in tools.items():
        if not shutil.which(cmd):
            missing_tools.append(name)
    
    if missing_tools:
        console.print(f"[yellow]Warning:[/yellow] Missing security tools: {', '.join(missing_tools)}")
        install = Prompt.ask("Do you want to install missing tools? (y/n)", choices=["y", "n"], default="y")
        if install.lower() == "y":
            install_tools(missing_tools)
        else:
            console.print("[yellow]Skipping installation of missing tools.[/yellow]")
            logging.warning(f"Missing tools not installed: {', '.join(missing_tools)}")
    else:
        console.print("[green]All required security tools are installed.[/green]")
        logging.info("All required security tools are installed.")

def check_firewall():
    """Check if the firewall (UFW) is enabled and offer to enable it if not."""
    log_section("Checking Firewall Status")
    
    if not shutil.which("ufw"):
        console.print("[red]Error:[/red] UFW (firewall) is not installed. Skipping firewall check.")
        logging.error("UFW (firewall) is not installed. Skipping firewall check.")
        return
    
    try:
        result = subprocess.run(["sudo", "ufw", "status"], capture_output=True, text=True)
        
        if "Status: active" in result.stdout:
            console.print("[green]Firewall is enabled.[/green]")
            logging.info("Firewall is enabled.")
        else:
            console.print("[red]Warning:[/red] Firewall is not enabled.")
            enable = Prompt.ask("Do you want to enable the firewall? (y/n)", choices=["y", "n"], default="y")
            if enable.lower() == "y":
                subprocess.run(["sudo", "ufw", "enable"], check=True)
                console.print("[green]Firewall has been enabled.[/green]")
                logging.info("Firewall has been enabled.")
            else:
                console.print("[yellow]Firewall remains disabled.[/yellow]")
                logging.warning("Firewall remains disabled.")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error checking firewall status: {e}[/red]")
        logging.error(f"Error checking firewall status: {e}")

def scan_files():
    """Scan all files on the system for malware using ClamAV."""
    log_section("Running ClamAV Scan")
    
    if not shutil.which("clamscan"):
        console.print("[red]Error:[/red] ClamAV is not installed. Skipping scan.")
        logging.error("ClamAV is not installed. Skipping scan.")
        return
    
    try:
        result = subprocess.run(["clamscan", "--recursive", "--infected", "/"], capture_output=True, text=True)
        
        if result.returncode == 0:
            console.print("[green]No malware found.[/green]")
            logging.info("No malware found during ClamAV scan.")
        else:
            console.print("[yellow]Potential threats detected:[/yellow]")
            console.print(result.stdout)
            logging.warning(f"Potential threats detected: {result.stdout}")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error during ClamAV scan: {e}[/red]")
        logging.error(f"Error during ClamAV scan: {e}")

def check_open_ports():
    """Check for unnecessary open ports and offer to close them."""
    log_section("Checking Open Ports")
    try:
        result = subprocess.run(["ss", "-tuln"], capture_output=True, text=True)
        console.print(result.stdout)
        
        # Look for suspicious open ports or known ports that shouldn't be open
        suspicious_ports = ['22', '23', '3306']  # Example of ports (SSH, Telnet, MySQL) that shouldn't be open by default
        for line in result.stdout.splitlines():
            for port in suspicious_ports:
                if f":{port}" in line:
                    console.print(f"[red]Warning:[/red] Suspicious open port found: {line.strip()}")
                    logging.warning(f"Suspicious open port found: {line.strip()}")
                    close = Prompt.ask("Do you want to close this port? (y/n)", choices=["y", "n"], default="y")
                    if close.lower() == "y":
                        # Check if the rule already exists
                        ufw_status = subprocess.run(["sudo", "ufw", "status"], capture_output=True, text=True)
                        if f"{port}/tcp" in ufw_status.stdout or f"{port}/udp" in ufw_status.stdout:
                            console.print(f"[yellow]Rule for port {port} already exists. Skipping.[/yellow]")
                            logging.info(f"Rule for port {port} already exists. Skipping.")
                        else:
                            try:
                                # Add deny rule for the port
                                subprocess.run(["sudo", "ufw", "deny", port], check=True)
                                console.print(f"[green]Port {port} has been closed.[/green]")
                                logging.info(f"Port {port} has been closed.")
                                # Reload UFW to apply changes
                                subprocess.run(["sudo", "ufw", "reload"], check=True)
                                console.print("[green]UFW rules reloaded.[/green]")
                                logging.info("UFW rules reloaded.")
                            except subprocess.CalledProcessError as e:
                                console.print(f"[red]Error closing port {port}: {e}[/red]")
                                logging.error(f"Error closing port {port}: {e}")
                    else:
                        console.print(f"[yellow]Port {port} remains open.[/yellow]")
                        logging.info(f"Port {port} remains open.")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error checking open ports: {e}[/red]")
        logging.error(f"Error checking open ports: {e}")

def check_for_updates():
    """Check if system updates are available."""
    log_section("Checking for System Updates")
    try:
        # Refresh package list
        subprocess.run(["sudo", "pacman", "-Sy", "--noconfirm"], capture_output=True, text=True)
        
        # Check for updates
        update_available = subprocess.run(["sudo", "pacman", "-Qu"], capture_output=True, text=True)
        
        if update_available.stdout.strip():
            console.print("[yellow]Updates available:[/yellow]")
            console.print(update_available.stdout)
            logging.warning(f"Updates available: {update_available.stdout}")
        else:
            console.print("[green]System is up-to-date.[/green]")
            logging.info("System is up-to-date.")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error checking for updates: {e}[/red]")
        logging.error(f"Error checking for updates: {e}")

def check_ssh_security():
    """Check SSH security configurations."""
    log_section("Checking SSH Security")
    
    ssh_config_path = "/etc/ssh/sshd_config"
    if os.path.exists(ssh_config_path):
        try:
            with open(ssh_config_path, "r") as file:
                config = file.read()
            
            if "PasswordAuthentication yes" in config:
                console.print("[red]Warning:[/red] Password authentication is enabled. Consider disabling it.")
                logging.warning("Password authentication is enabled.")
            else:
                console.print("[green]Password authentication is disabled.[/green]")
                logging.info("Password authentication is disabled.")
        except Exception as e:
            console.print(f"[red]Error reading SSH config: {e}[/red]")
            logging.error(f"Error reading SSH config: {e}")
    else:
        console.print("[yellow]Warning:[/yellow] SSH config not found.")
        logging.warning("SSH config not found.")

def check_file_permissions():
    """Check for weak file permissions and provide an option to fix them."""
    log_section("Checking File Permissions")
    suspicious_files = []
    
    try:
        for root, _, files in os.walk("/"):
            for file in files:
                path = os.path.join(root, file)
                if os.path.exists(path):
                    mode = oct(os.stat(path).st_mode)[-3:]
                    if mode in ["777", "666"]:  # Too open
                        suspicious_files.append(path)
        
        if suspicious_files:
            console.print("[yellow]Warning:[/yellow] These files have weak permissions:")
            for file in suspicious_files:
                console.print(f"[yellow]{file}[/yellow]")
            
            fix = Prompt.ask("Do you want to fix permissions for all weak files? (y/n)", choices=["y", "n"], default="n")
            if fix.lower() == "y":
                for file in suspicious_files:
                    os.chmod(file, 0o644 if not os.access(file, os.X_OK) else 0o755)
                    console.print(f"[green]Fixed permissions for {file}[/green]")
                logging.info(f"Fixed permissions for {len(suspicious_files)} files.")
            else:
                console.print("[green]No changes made to file permissions.[/green]")
                logging.info("No changes made to file permissions.")
        else:
            console.print("[green]No weak file permissions found.[/green]")
            logging.info("No weak file permissions found.")
    except Exception as e:
        console.print(f"[red]Error checking file permissions: {e}[/red]")
        logging.error(f"Error checking file permissions: {e}")

def check_rootkits():
    """Check for rootkits using rkhunter."""
    log_section("Checking for Rootkits")
    
    if not shutil.which("rkhunter"):
        console.print("[red]Error:[/red] rkhunter is not installed. Skipping rootkit check.")
        logging.error("rkhunter is not installed. Skipping rootkit check.")
        return
    
    try:
        result = subprocess.run(["sudo", "rkhunter", "--check"], capture_output=True, text=True)
        console.print(result.stdout)
        
        if "Warning" in result.stdout:
            console.print("[red]Warning:[/red] Potential rootkit activity detected.")
            logging.warning("Potential rootkit activity detected.")
        else:
            console.print("[green]No rootkit activity detected.[/green]")
            logging.info("No rootkit activity detected.")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error during rootkit check: {e}[/red]")
        logging.error(f"Error during rootkit check: {e}")

def enable_fail2ban():
    """Enable fail2ban to protect against brute-force attacks."""
    log_section("Enabling Fail2Ban")
    
    if not shutil.which("fail2ban-client"):
        console.print("[red]Error:[/red] fail2ban is not installed. Skipping fail2ban setup.")
        logging.error("fail2ban is not installed. Skipping fail2ban setup.")
        return
    
    try:
        subprocess.run(["sudo", "systemctl", "enable", "fail2ban"], check=True)
        subprocess.run(["sudo", "systemctl", "start", "fail2ban"], check=True)
        console.print("[green]fail2ban has been enabled and started.[/green]")
        logging.info("fail2ban has been enabled and started.")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error enabling fail2ban: {e}[/red]")
        logging.error(f"Error enabling fail2ban: {e}")

def enable_auditd():
    """Enable auditd for system auditing."""
    log_section("Enabling Auditd")
    
    if not shutil.which("auditctl"):
        console.print("[red]Error:[/red] auditd is not installed. Skipping auditd setup.")
        logging.error("auditd is not installed. Skipping auditd setup.")
        return
    
    try:
        subprocess.run(["sudo", "systemctl", "enable", "auditd"], check=True)
        subprocess.run(["sudo", "systemctl", "start", "auditd"], check=True)
        console.print("[green]auditd has been enabled and started.[/green]")
        logging.info("auditd has been enabled and started.")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error enabling auditd: {e}[/red]")
        logging.error(f"Error enabling auditd: {e}")

def check_unnecessary_services():
    """Check for unnecessary services running."""
    log_section("Checking Unnecessary Services")
    try:
        result = subprocess.run(["systemctl", "list-unit-files", "--state=enabled"], capture_output=True, text=True)
        console.print(result.stdout)
        
        # Example: Check for common unnecessary services
        unnecessary_services = ["cups.service", "bluetooth.service"]
        for service in unnecessary_services:
            if service in result.stdout:
                console.print(f"[red]Warning:[/red] Unnecessary service found: {service}")
                logging.warning(f"Unnecessary service found: {service}")
                disable = Prompt.ask(f"Do you want to disable {service}? (y/n)", choices=["y", "n"], default="y")
                if disable.lower() == "y":
                    try:
                        subprocess.run(["sudo", "systemctl", "disable", service], check=True)
                        console.print(f"[green]{service} has been disabled.[/green]")
                        logging.info(f"{service} has been disabled.")
                    except subprocess.CalledProcessError as e:
                        console.print(f"[red]Error disabling {service}: {e}[/red]")
                        logging.error(f"Error disabling {service}: {e}")
                else:
                    console.print(f"[yellow]{service} remains enabled.[/yellow]")
                    logging.info(f"{service} remains enabled.")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error checking services: {e}[/red]")
        logging.error(f"Error checking services: {e}")

def check_selinux_apparmor():
    """Check if SELinux or AppArmor is enabled."""
    log_section("Checking SELinux/AppArmor Status")
    
    # Skip SELinux check on Arch Linux
    console.print("[yellow]SELinux is not used on Arch Linux. Skipping check.[/yellow]")
    logging.info("SELinux is not used on Arch Linux. Skipping check.")
    
    # Check AppArmor (only if aa-status is available)
    if shutil.which("aa-status"):
        try:
            apparmor_result = subprocess.run(["aa-status"], capture_output=True, text=True)
            if "apparmor module is loaded" in apparmor_result.stdout:
                console.print("[green]AppArmor is enabled.[/green]")
                logging.info("AppArmor is enabled.")
            else:
                console.print("[red]Warning:[/red] AppArmor is not enabled.")
                logging.warning("AppArmor is not enabled.")
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Error checking AppArmor: {e}[/red]")
            logging.error(f"Error checking AppArmor: {e}")
    else:
        console.print("[yellow]AppArmor is not installed or not supported on this system.[/yellow]")
        logging.info("AppArmor is not installed or not supported on this system.")

def check_password_policy():
    """Check if password policies are enforced."""
    log_section("Checking Password Policies")
    try:
        result = subprocess.run(["grep", "^PASS_MAX_DAYS", "/etc/login.defs"], capture_output=True, text=True)
        if result.stdout:
            console.print(f"[green]Password policy found: {result.stdout.strip()}[/green]")
            logging.info(f"Password policy found: {result.stdout.strip()}")
        else:
            console.print("[red]Warning:[/red] No password policy found.")
            logging.warning("No password policy found.")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error checking password policy: {e}[/red]")
        logging.error(f"Error checking password policy: {e}")

def enable_reminders():
    """Ask the user if they want to enable monthly or weekly reminders to run the script."""
    log_section("Setting Up Reminders")
    reminder_choice = Prompt.ask("Would you like to set up regular reminders to run this script? (weekly/monthly/n)", choices=["weekly", "monthly", "n"], default="n")
    
    if reminder_choice == "weekly":
        cron_expression = "0 0 * * 0"  # Every Sunday at midnight
        setup_reminder(cron_expression)
    elif reminder_choice == "monthly":
        cron_expression = "0 0 1 * *"  # First day of the month at midnight
        setup_reminder(cron_expression)
    else:
        console.print("[green]No reminders will be set.[/green]")
        logging.info("No reminders set.")

def setup_reminder(cron_expression):
    """Setup a cron job to run the script at the given time."""
    script_path = os.path.abspath(__file__)
    cron_command = f"{cron_expression} /usr/bin/python3 {script_path}"
    try:
        subprocess.run(f"(crontab -l; echo \"{cron_command}\") | crontab -", shell=True, check=True)
        console.print(f"[green]Reminder set to run the script at: {cron_expression}[/green]")
        logging.info(f"Reminder set with cron expression: {cron_expression}")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error setting reminder: {e}[/red]")
        logging.error(f"Error setting reminder: {e}")

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    console.print(Panel("Protective Beaver", style="bold purple", expand=False))
    check_tools()
    check_firewall()
    scan_files()
    check_open_ports()
    check_for_updates()
    check_ssh_security()
    check_file_permissions()
    check_rootkits()
    enable_fail2ban()
    enable_auditd()
    check_unnecessary_services()
    check_selinux_apparmor()  # Updated function
    check_password_policy()
    enable_reminders()

    # Goodbye message
    console.print(Panel("[bold green]Script execution complete. Goodbye![/bold green]", style="bold purple"))

if __name__ == "__main__":
    main()
