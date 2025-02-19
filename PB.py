import os
import subprocess
import re
import shutil
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
import logging

console = Console()

# Set up logging to track script execution and results
logging.basicConfig(filename="security_script.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def check_tools():
    """Check if required security tools are installed."""
    tools = {"ClamAV": "clamscan", "rkhunter": "rkhunter", "fail2ban": "fail2ban-client"}
    missing_tools = []
    
    for name, cmd in tools.items():
        if not shutil.which(cmd):
            missing_tools.append(name)
    
    if missing_tools:
        console.print(f"[yellow]Warning:[/yellow] Missing security tools: {', '.join(missing_tools)}")
        console.print(f"To install, use: [cyan]sudo pacman -S {', '.join(missing_tools)}[/cyan]")
        logging.warning(f"Missing security tools: {', '.join(missing_tools)}")
    else:
        console.print("[green]All required security tools are installed.[/green]")
        logging.info("All required security tools are installed.")

def scan_files():
    """Scan all files on the system for malware using ClamAV."""
    console.print(Panel("Running ClamAV scan on the system...", style="bold blue"))
    
    if not shutil.which("clamscan"):
        console.print("[red]Error:[/red] ClamAV is not installed. Skipping scan.")
        logging.error("ClamAV is not installed. Skipping scan.")
        return
    
    result = subprocess.run(["clamscan", "--recursive", "--infected", "/"], capture_output=True, text=True)
    
    if result.returncode == 0:
        console.print("[green]No malware found.[/green]")
        logging.info("No malware found during ClamAV scan.")
    else:
        console.print("[yellow]Potential threats detected:[/yellow]")
        console.print(result.stdout)
        logging.warning(f"Potential threats detected: {result.stdout}")

def check_open_ports():
    """Check for unnecessary open ports."""
    console.print(Panel("Checking for open ports...", style="bold yellow"))
    result = subprocess.run(["ss", "-tuln"], capture_output=True, text=True)
    console.print(result.stdout)
    
    # Look for suspicious open ports or known ports that shouldn't be open
    suspicious_ports = ['22', '23', '3306']  # Example of ports (SSH, Telnet, MySQL) that shouldn't be open by default
    for line in result.stdout.splitlines():
        for port in suspicious_ports:
            if port in line:
                console.print(f"[red]Warning:[/red] Suspicious open port found: {line.strip()}")
                logging.warning(f"Suspicious open port found: {line.strip()}")

def check_for_updates():
    """Check if system updates are available."""
    console.print(Panel("Checking for system updates...", style="bold green"))
    result = subprocess.run(["sudo", "pacman", "-Sy", "--noconfirm"], capture_output=True, text=True)
    
    if "error" in result.stderr:
        console.print("[red]Error checking for updates.[/red]")
        logging.error("Error checking for updates.")
    else:
        console.print("[green]System update check complete.[/green]")
        logging.info("System update check complete.")
        
    update_available = subprocess.run(["sudo", "pacman", "-Qu"], capture_output=True, text=True)
    
    if update_available.stdout.strip():
        console.print("[yellow]Updates available:[/yellow]")
        console.print(update_available.stdout)
        logging.warning(f"Updates available: {update_available.stdout}")
    else:
        console.print("[green]No updates available.[/green]")
        logging.info("No updates available.")

def check_ssh_security():
    """Check SSH security configurations."""
    console.print(Panel("Checking SSH security...", style="bold cyan"))
    
    ssh_config_path = "/etc/ssh/sshd_config"
    if os.path.exists(ssh_config_path):
        with open(ssh_config_path, "r") as file:
            config = file.read()
        
        if "PasswordAuthentication yes" in config:
            console.print("[red]Warning:[/red] Password authentication is enabled. Consider disabling it.")
            logging.warning("Password authentication is enabled.")
        else:
            console.print("[green]Password authentication is disabled.[/green]")
            logging.info("Password authentication is disabled.")
    else:
        console.print("[yellow]Warning:[/yellow] SSH config not found.")
        logging.warning("SSH config not found.")

def check_file_permissions():
    """Check for weak file permissions and provide an option to fix them."""
    console.print(Panel("Checking file permissions...", style="bold magenta"))
    suspicious_files = []
    
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

def enable_reminders():
    """Ask the user if they want to enable monthly or weekly reminders to run the script."""
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
    cron_command = f"{cron_expression} /usr/bin/python3 /path/to/your/script.py"
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
    scan_files()
    check_open_ports()
    check_for_updates()
    check_ssh_security()
    check_file_permissions()
    enable_reminders()

if __name__ == "__main__":
    main()
