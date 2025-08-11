#!/usr/bin/env python3
"""
ARP Spoofing Detector + Mitigation (Windows) - Updated Version
Features:
- Auto-detect default gateway
- Periodic check of gateway MAC
- TTS or beep alert + GUI popup on detection
- Auto-restore original ARP entry (static)
- Manual blocking with confirmation prompts
- Option to check & delete previous blockings
- Tray icon + Start/Stop monitoring + Enable/Disable Auto-Restore via GUI
- Logging to arp_spoof_log.txt

NOTE: This tool requires Administrator privileges for ARP modifications and firewall rules.
"""

import os
import time
import subprocess
import tkinter as tk
from tkinter import messagebox, simpledialog
import re
from datetime import datetime
import threading
import pystray
from PIL import Image, ImageDraw
import winsound
import pyttsx3
import psutil
import sys

# ---------------- Configuration ----------------
CHECK_INTERVAL = 10  # seconds
LOG_FILE = "arp_spoof_log.txt"
monitoring = False
tray_icon = None

# Alert system
ALERT_MODE = "tts"  # Options: 'beep', 'tts'
AUTO_RESTORE_ENABLED = True  # Toggle auto restore ARP
AUTO_BLOCK_ENABLED = False  # Manual blocking with confirmation

# Keep track of blocked IPs so we can optionally clean up
blocked_ips = set()
FIREWALL_RULE_PREFIX = "ARP_Detector_Block_"

# ---------------- Helper Functions ----------------
def run_cmd(cmd):
    """Run a shell command and return (returncode, stdout)."""
    try:
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return proc.returncode, proc.stdout.strip()
    except Exception as e:
        return -1, str(e)

def get_default_gateway():
    """Detect default gateway from ipconfig output (Windows)."""
    try:
        code, output = run_cmd("ipconfig")
        if code != 0:
            print("ipconfig failed:", output)
            return None
        matches = re.findall(r"Default Gateway[ .:]*([\d.]+)", output)
        for gw in matches:
            if gw and re.match(r"(\d{1,3}\.){3}\d{1,3}", gw) and not gw.startswith("0"):
                return gw.strip()
    except Exception as e:
        print(f"Error detecting default gateway: {e}")
    return None

def get_mac(ip):
    """Return MAC for given IP using arp -a <ip> parsing."""
    try:
        code, output = run_cmd(f"arp -a {ip}")
        if code != 0:
            code, output = run_cmd("arp -a")
        match = re.search(r"([0-9a-f]{2}-){5}[0-9a-f]{2}", output, re.IGNORECASE)
        if match:
            return match.group(0).lower()
    except Exception as e:
        print(f"Error fetching MAC: {e}")
    return None

def find_ips_by_mac(mac):
    """Parse arp -a and return list of IPs that map to the provided MAC."""
    ips = []
    try:
        code, output = run_cmd("arp -a")
        if code != 0:
            return ips
        lines = output.splitlines()
        for line in lines:
            if mac.lower() in line.lower():
                m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                if m:
                    ips.append(m.group(1))
    except Exception as e:
        print("Error finding IPs by MAC:", e)
    return list(set(ips))

def speak_alert():
    """Text-to-speech alert."""
    try:
        engine = pyttsx3.init()
        engine.say("Warning! ARP spoofing detected. The gateway MAC address has changed.")
        engine.runAndWait()
    except Exception as e:
        print("TTS Error:", e)

def show_alert():
    """Play alert (beep/TTS) and show popup."""
    if ALERT_MODE == "beep":
        try:
            winsound.MessageBeep(winsound.MB_ICONHAND)
        except Exception:
            pass
    elif ALERT_MODE == "tts":
        speak_alert()

    try:
        root = tk.Tk()
        root.withdraw()
        messagebox.showwarning("⚠️ ARP Spoofing Alert!", "Possible ARP Spoofing Detected!\nGateway MAC has changed.")
        root.destroy()
    except Exception as e:
        print("Popup error:", e)

def log_alert(original_mac, current_mac):
    """Append alert to log file with timestamp."""
    try:
        with open(LOG_FILE, "a") as log:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log.write(f"[{timestamp}] ALERT: Gateway MAC changed!\n")
            log.write(f"    Original: {original_mac}\n    Current: {current_mac}\n\n")
    except Exception as e:
        print("Logging error:", e)

def restore_arp_entry(ip, mac):
    """Restore ARP by deleting dynamic entry and adding static mapping."""
    try:
        run_cmd(f"arp -d {ip}")
        run_cmd(f"arp -s {ip} {mac}")
        print(f"[+] Restored ARP entry: {ip} -> {mac}")
        return True
    except Exception as e:
        print(f"[-] Failed to restore ARP entry: {e}")
        return False

def block_attacker_ip(ip):
    """Add Windows Firewall rules to block inbound & outbound traffic."""
    try:
        rule_name_in = FIREWALL_RULE_PREFIX + ip + "_IN"
        rule_name_out = FIREWALL_RULE_PREFIX + ip + "_OUT"
        ret1, out1 = run_cmd(f'netsh advfirewall firewall add rule name="{rule_name_in}" dir=in action=block remoteip={ip}')
        ret2, out2 = run_cmd(f'netsh advfirewall firewall add rule name="{rule_name_out}" dir=out action=block remoteip={ip}')
        if ret1 == 0 and ret2 == 0:
            # Verify rules exist
            code_in, output_in = run_cmd(f'netsh advfirewall firewall show rule name="{rule_name_in}"')
            code_out, output_out = run_cmd(f'netsh advfirewall firewall show rule name="{rule_name_out}"')
            if code_in == 0 and code_out == 0 and rule_name_in in output_in and rule_name_out in output_out:
                blocked_ips.add(ip)
                print(f"[+] Firewall blocked IP: {ip}")
                return True
            else:
                print(f"[-] Firewall rules not found after adding for IP {ip}. Inbound output: {output_in}, Outbound output: {output_out}")
                return False
        else:
            print(f"[-] Failed to block IP {ip}: Inbound: {out1}, Outbound: {out2}")
            return False
    except Exception as e:
        print(f"[-] Failed to block IP {ip}: {e}")
        return False

def unblock_attacker_ip(ip):
    """Remove firewall rules added for a blocked IP."""
    try:
        rule_name_in = FIREWALL_RULE_PREFIX + ip + "_IN"
        rule_name_out = FIREWALL_RULE_PREFIX + ip + "_OUT"
        run_cmd(f'netsh advfirewall firewall delete rule name="{rule_name_in}"')
        run_cmd(f'netsh advfirewall firewall delete rule name="{rule_name_out}"')
        if ip in blocked_ips:
            blocked_ips.remove(ip)
        print(f"[+] Removed firewall block for IP: {ip}")
    except Exception as e:
        print(f"[-] Failed to remove firewall rule for {ip}: {e}")

def cleanup_all_blocked_ips():
    """Cleanup all blocked IP firewall rules created by this tool."""
    for ip in list(blocked_ips):
        unblock_attacker_ip(ip)

def get_blocked_ips_list():
    """Get list of currently blocked IPs from firewall rules."""
    blocked = []
    try:
        code, output = run_cmd('netsh advfirewall firewall show rule name=all')
        if code == 0:
            lines = output.splitlines()
            for line in lines:
                if FIREWALL_RULE_PREFIX in line:
                    match = re.search(r'ARP_Detector_Block_([\d.]+)', line)
                    if match:
                        ip = match.group(1)
                        if ip not in blocked:
                            blocked.append(ip)
    except Exception as e:
        print(f"[-] Failed to get blocked IPs: {e}")
    return blocked

def prompt_for_blocking(attacker_ips):
    """Prompt user for confirmation before blocking IPs."""
    if not attacker_ips:
        return []
    
    root = tk.Tk()
    root.withdraw()
    
    ip_list = "\n".join(attacker_ips)
    message = f"Potential attacker IPs detected:\n\n{ip_list}\n\nDo you want to block these IPs?"
    
    result = messagebox.askyesno("Block IPs?", message)
    root.destroy()
    
    if result:
        return attacker_ips
    return []

# ---------------- Core Monitoring ----------------
def monitor():
    global monitoring
    gateway_ip = get_default_gateway()
    if not gateway_ip:
        print("[-] Could not detect default gateway. Monitoring aborted.")
        return

    print(f"[+] Detected Gateway IP: {gateway_ip}")
    original_mac = get_mac(gateway_ip)
    if not original_mac:
        print("[-] Could not fetch original MAC address. Monitoring aborted.")
        return

    print(f"[+] Original Gateway MAC: {original_mac}")

    # Track attacker MACs seen and their IPs
    attacker_mac_ip_map = {}

    while monitoring:
        try:
            current_mac = get_mac(gateway_ip)
            if current_mac and current_mac != original_mac:
                print("[!] ALERT: Gateway MAC address changed!")
                print(f"    Original: {original_mac} | Current: {current_mac}")
                log_alert(original_mac, current_mac)
                show_alert()

                if AUTO_RESTORE_ENABLED:
                    restored = restore_arp_entry(gateway_ip, original_mac)

                    # Find potential attacker IPs
                    attacker_ips = find_ips_by_mac(current_mac)
                    if attacker_ips:
                        attacker_ips = [ip for ip in attacker_ips if ip != gateway_ip]

                        # Check if this MAC has been seen with different IPs
                        prev_ips = attacker_mac_ip_map.get(current_mac, set())
                        new_ips = set(attacker_ips) - prev_ips
                        if new_ips:
                            print(f"[!] New IPs detected for attacker MAC {current_mac}: {new_ips}")
                            attacker_mac_ip_map[current_mac] = prev_ips.union(new_ips)
                            # Alert user about new IPs for same MAC
                            root = tk.Tk()
                            root.withdraw()
                            messagebox.showwarning("Repeated Attacker MAC Detected",
                                f"Attacker MAC {current_mac} detected with new IP(s):\n" + "\n".join(new_ips))
                            root.destroy()

                        # Display attacker IPs in GUI and console
                        attacker_ip_str = ', '.join(attacker_ips)
                        print(f"[!] Attacker IPs detected: {attacker_ip_str}")

                        # Show attacker IPs in a popup info box
                        root = tk.Tk()
                        root.withdraw()
                        messagebox.showinfo("Attacker IPs Detected", f"Attacker IP addresses:\n{attacker_ip_str}")
                        root.destroy()
            time.sleep(CHECK_INTERVAL)
        except Exception as e:
            print("Monitoring loop error:", e)
            time.sleep(CHECK_INTERVAL)


# ---------------- GUI & Tray ----------------
def start_monitoring():
    global monitoring
    if not monitoring:
        monitoring = True
        threading.Thread(target=monitor, daemon=True).start()

def stop_monitoring():
    global monitoring
    monitoring = False

def create_tray_icon():
    global tray_icon
    try:
        icon_path = os.path.join(os.path.dirname(__file__), "arp_icon.ico")
        if os.path.exists(icon_path):
            icon_image = Image.open(icon_path)
        else:
            icon_image = Image.new('RGB', (64, 64), "white")
            d = ImageDraw.Draw(icon_image)
            d.ellipse((16, 16, 48, 48), fill="red")
    except Exception:
        icon_image = Image.new('RGB', (64, 64), "white")
        d = ImageDraw.Draw(icon_image)
        d.ellipse((16, 16, 48, 48), fill="red")

    def on_start(icon, item):
        start_monitoring()

    def on_stop(icon, item):
        stop_monitoring()

    def on_exit(icon, item):
        try:
            icon.stop()
        except Exception:
            pass

    tray_icon = pystray.Icon("ARP Detector", icon_image, "ARP Monitor", menu=pystray.Menu(
        pystray.MenuItem("Start Monitoring", on_start),
        pystray.MenuItem("Stop Monitoring", on_stop),
        pystray.MenuItem("Exit", on_exit)
    ))
    tray_icon.run()

def start_gui():
    global AUTO_RESTORE_ENABLED
    root = tk.Tk()
    root.title("ARP Spoofing Detector")
    root.geometry("400x320")

    status_label = tk.Label(root, text="Status: Not Monitoring", fg="red", font=("Segoe UI", 11))
    status_label.pack(pady=12)

    def start():
        start_monitoring()
        status_label.config(text="Status: Monitoring", fg="green")

    def stop():
        stop_monitoring()
        status_label.config(text="Status: Not Monitoring", fg="red")

    def toggle_auto_restore():
        nonlocal auto_restore_var
        global AUTO_RESTORE_ENABLED
        AUTO_RESTORE_ENABLED = auto_restore_var.get()

    def view_blocked_ips():
        """Show dialog with currently blocked IPs"""
        blocked = get_blocked_ips_list()
        if blocked:
            ip_list = "\n".join(blocked)
            messagebox.showinfo("Blocked IPs", f"Currently blocked IPs:\n\n{ip_list}")
        else:
            messagebox.showinfo("Blocked IPs", "No IPs are currently blocked by this tool.")

    def manage_blocked_ips():
        """Allow user to selectively unblock IPs"""
        blocked = get_blocked_ips_list()
        if not blocked:
            messagebox.showinfo("Manage Blocks", "No IPs are currently blocked.")
            return
            
        selection_window = tk.Toplevel(root)
        selection_window.title("Manage Blocked IPs")
        selection_window.geometry("300x200")
        
        listbox = tk.Listbox(selection_window, selectmode=tk.MULTIPLE)
        listbox.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        
        for ip in blocked:
            listbox.insert(tk.END, ip)
        
        def unblock_selected():
            selected = [listbox.get(i) for i in listbox.curselection()]
            for ip in selected:
                unblock_attacker_ip(ip)
            selection_window.destroy()
            messagebox.showinfo("Success", f"Unblocked {len(selected)} IP(s)")
        
        unblock_btn = tk.Button(selection_window, text="Unblock Selected", command=unblock_selected)
        unblock_btn.pack(pady=5)

    start_button = tk.Button(root, text="Start Monitoring", width=20, command=start)
    start_button.pack(pady=6)

    stop_button = tk.Button(root, text="Stop Monitoring", width=20, command=stop)
    stop_button.pack(pady=6)

    tray_button = tk.Button(root, text="Minimize to Tray", width=20,
                            command=lambda: [root.withdraw(), threading.Thread(target=create_tray_icon, daemon=True).start()])
    tray_button.pack(pady=6)

    auto_restore_var = tk.BooleanVar(value=AUTO_RESTORE_ENABLED)
    auto_restore_check = tk.Checkbutton(root, text="Enable Auto Restore ARP", variable=auto_restore_var, command=toggle_auto_restore)
    auto_restore_check.pack(pady=10)

    alert_mode_label = tk.Label(root, text="Alert Mode: " + ("TTS" if ALERT_MODE == "tts" else "Beep"))
    alert_mode_label.pack(pady=6)

    # Removed buttons for managing blocks as per user request
    # view_blocks_btn = tk.Button(root, text="View Blocked IPs", width=20, command=view_blocked_ips)
    # view_blocks_btn.pack(pady=6)

    # manage_blocks_btn = tk.Button(root, text="Manage Blocked IPs", width=20, command=manage_blocked_ips)
    # manage_blocks_btn.pack(pady=6)

    cleanup_button = tk.Button(root, text="Remove All Firewall Blocks", width=20, command=cleanup_all_blocked_ips)
    cleanup_button.pack(pady=6)

    root.protocol("WM_DELETE_WINDOW", lambda: [root.withdraw(), threading.Thread(target=create_tray_icon, daemon=True).start()])
    root.mainloop()

# ---------------- Main Entry ----------------
if __name__ == "__main__":
    # Basic admin privilege check (best-effort)
    if os.name == "nt":
        try:
            code, _ = run_cmd("net session")
            if code != 0:
                print("[!] Warning: It looks like the script is not running with Administrator privileges.")
                print("    Some features (ARP restore / firewall) may fail without admin rights.")
                print("    Press Enter to continue anyway, or Ctrl+C to exit...")
                input()
        except Exception:
            pass

    print("[*] Launching ARP Spoofing Detector GUI")
    
    try:
        start_gui()
    except KeyboardInterrupt:
        print("\n[*] ARP Spoofing Detector stopped by user")
    except Exception as e:
        print(f"[!] Error: {e}")
        print("Press Enter to exit...")
        input()
