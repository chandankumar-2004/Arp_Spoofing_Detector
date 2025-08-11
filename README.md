# ARP Spoofing Detector + Mitigation (Windows)

![Network Security](https://img.shields.io/badge/Network-Security-blue)
![Python](https://img.shields.io/badge/Python-3.x-green)
![Windows](https://img.shields.io/badge/Platform-Windows-lightgrey)

---

## 🚀 Overview

Protect your network from ARP spoofing attacks with this powerful and easy-to-use Windows tool. ARP spoofing is a serious threat that allows attackers to intercept or manipulate your network traffic by impersonating your default gateway. This tool continuously monitors your network, alerts you instantly on suspicious activity, and helps you mitigate risks effectively.

---

## 🎯 Why Choose This Tool?

- **Real-time Monitoring:** Automatically detects changes in your default gateway's MAC address.
- **Instant Alerts:** Audio (beep or text-to-speech) and popup notifications keep you informed.
- **Auto-Restore:** Automatically fixes your ARP table to prevent traffic interception.
- **Attacker IP Identification:** Displays IP addresses linked to suspicious MAC addresses.
- **User-Friendly GUI:** Intuitive controls with system tray integration for seamless operation.
- **Comprehensive Logging:** Keeps detailed logs for audit and review.

---

## ⚙️ How It Works

1. **Detects your default gateway IP** automatically.
2. **Monitors the MAC address** associated with the gateway periodically.
3. **Detects any unexpected MAC changes** indicating possible ARP spoofing.
4. **Alerts you immediately** with audio and visual notifications.
5. **Restores the original ARP entry** to maintain network integrity.
6. **Identifies attacker IPs** associated with suspicious MAC addresses.
7. **Displays attacker IPs** for your awareness (blocking is not performed).

---

## ✨ Features

- Auto-detection of default gateway IP
- Periodic MAC address verification
- Audio alerts: beep or text-to-speech
- Visual popup alerts
- Automatic ARP entry restoration
- Attacker IP address display
- System tray integration with start/stop controls
- Detailed logging to `arp_spoof_log.txt`

---

## 🛠️ Requirements

- Windows 10/11
- Python 3.x (added to PATH)
- Administrator privileges (required for ARP and network modifications)
- Python packages:
  - pystray
  - pillow
  - pyttsx3
  - psutil
  - winsound (built-in on Windows)

Install dependencies with:

```bash
pip install pystray pillow pyttsx3 psutil
```

---

## 🚀 Installation & Usage

1. Download the tool files:
   - `arp_spoof_detector_updated.py`
   - `run_arp_detector_admin.bat` (recommended for easy admin launch)

2. Run the tool as Administrator:
   - Double-click `run_arp_detector_admin.bat` and accept the UAC prompt.
   - Or open Command Prompt as Administrator and run:
     ```bash
     python arp_spoof_detector_updated.py
     ```

3. Use the GUI:
   - Click **Start Monitoring** to begin detection.
   - Receive alerts on suspicious activity.
   - View attacker IP addresses in popup and console.
   - Minimize to tray to keep running in the background.

---

## 💡 Notes

- This tool does **not** block attacker IPs automatically.
- Focuses on detection and alerting for your awareness.
- Logs are saved in `arp_spoof_log.txt` in the tool directory.
- Always run with Administrator privileges for full functionality.

---

## 🛠️ Troubleshooting

- Ensure Python and dependencies are installed.
- Run the tool as Administrator.
- Check `arp_spoof_log.txt` for detailed logs.
- Verify audio and popup permissions for alerts.

---

## 📄 License

Provided as-is without warranty. Use at your own risk.

---

## 📞 Contact

For support or feature requests, please contact the developer.

---

Thank you for choosing the ARP Spoofing Detector! Stay safe on your network.
