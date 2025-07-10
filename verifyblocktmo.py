
import subprocess
import time
import signal
import re
import os

INTERFACE = "eth0" 
CAPTURE_FILE = "tshark_full_output.txt"
TCP_FLAG_PATTERN = re.compile(r'\b(ACK|FIN|RST)\b', re.IGNORECASE)

print("Testing Network Connectivity Test #8 (Verify Block to TMO internal Address Space) ")

# 1. Making dumpcamp is executable
print("[*] Ensuring dumpcap is executable...")
subprocess.run(["sudo", "chmod", "+x", "/usr/bin/dumpcap"], check=True)

# 2. Starting tshark and writing to file
print(f"[*] Starting tshark on interface {INTERFACE}, writing to {CAPTURE_FILE}...")
with open(CAPTURE_FILE, "w") as capture_output:
    tshark_proc = subprocess.Popen(
        ["sudo","tshark", "-i", INTERFACE],
        stdout=capture_output,
        stderr=subprocess.DEVNULL
    )

# 3. Wait to ensure tshark is started properly 
time.sleep(3)

# 4. Run Nmap ping scan
print("[*] Running Nmap ping scan...")
subprocess.run(["nmap", "-sn", "10.0.0.0/8"], stdout=subprocess.DEVNULL)

# 5. Stopping tshark
print("[*] Stopping tshark...")
tshark_proc.send_signal(signal.SIGINT)
tshark_proc.wait()

# 6. Analyzing tshark output
print("[*] Checking for ACK, FIN, or RST flags...")

ip_arrow_pattern = re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*→")

with open(CAPTURE_FILE, "r") as f:
    matches = [
        line.strip()
        for line in f
        if TCP_FLAG_PATTERN.search(line) and ip_arrow_pattern.search(line)
    ]
if matches:
    print("\n[*] Matching TCP flag lines:")
    for line in matches:
        print(line)
else:
    print("[*] No active connections found (no ACK, FIN, or RST flags).")
