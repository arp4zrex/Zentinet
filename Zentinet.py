# Zentinet - Automated Cybersecurity Script

# Welcome to Zentinet! This script enhances system security by monitoring and responding to suspicious activities.
# It blocks malicious IPs, closes compromised sessions, and sends email alerts for security incidents.

# Author: arp4zrex 
# https://github.com/arp4zrex

import subprocess
import time
import re
import smtplib
import os
import hashlib
import socket
import psutil
import requests
from email.mime.text import MIMEText

SMTP_SERVER = 'smtp.your-server.com'
SMTP_PORT = 587
SMTP_USERNAME = 'your-email@your-domain.com'
SMTP_PASSWORD = 'your-password'
EMAIL_FROM = 'your-email@your-domain.com'
EMAIL_TO = ['security@your-domain.com']

def send_email(subject, message):
    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = EMAIL_FROM
    msg['To'] = ', '.join(EMAIL_TO)

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())

def block_ip(ip_address):
    result = subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'], capture_output=True, text=True)
    if result.returncode == 0:
        print(f'IP {ip_address} successfully blocked')
        send_email('IP Blocked', f'The IP {ip_address} has been blocked due to suspicious activity.')
    else:
        print(f'Error blocking IP {ip_address}: {result.stderr}')

def close_sessions(ip_address):

    result = subprocess.run(['pkill', '-f', f'sshd:.*{ip_address}'], capture_output=True, text=True)
    if result.returncode == 0:
        print(f'Sessions from IP {ip_address} successfully closed')
        send_email('Sessions Closed', f'Active sessions from IP {ip_address} have been closed.')

def monitor_auth_log():
    log_file = "/var/log/auth.log"
    failed_attempts = {}
    THRESHOLD = 5

    with open(log_file, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            if "Failed password" in line:
                ip_address = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line).group(1)
                if ip_address in failed_attempts:
                    failed_attempts[ip_address] += 1
                else:
                    failed_attempts[ip_address] = 1
                
                print(f'Failed attempt from IP {ip_address} - {failed_attempts[ip_address]} times')
                
                if failed_attempts[ip_address] >= THRESHOLD:
                    block_ip(ip_address)
                    close_sessions(ip_address)
                    failed_attempts[ip_address] = 0

            if "Accepted password" in line:
                ip_address = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line).group(1)
                
                send_email('Unusual Login Detected', f'Unusual login detected from IP {ip_address}. Please verify if this is legitimate.')

def monitor_network():
    THRESHOLD = 10000  
    previous_rx = 0
    network_interface = "eth0"  

    while True:
        with open(f'/sys/class/net/{network_interface}/statistics/rx_bytes', 'r') as f:
            rx_bytes = int(f.read().strip())
        
        if previous_rx != 0 and (rx_bytes - previous_rx) > THRESHOLD:
            print(f'Sudden spike in network traffic detected: {rx_bytes - previous_rx} bytes')
            send_email('Network Spike Detected', f'Sudden spike in network traffic detected: {rx_bytes - previous_rx} bytes')
        
        previous_rx = rx_bytes
        time.sleep(1)

def monitor_critical_files():
    critical_files = ['/etc/passwd', '/etc/shadow']
    file_hashes = {}

    for file in critical_files:
        with open(file, 'rb') as f:
            file_hashes[file] = hashlib.sha256(f.read()).hexdigest()

    while True:
        for file in critical_files:
            with open(file, 'rb') as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()
            
            if current_hash != file_hashes[file]:
                print(f'Critical file {file} has been changed')
                send_email('Critical File Change Detected', f'Critical file {file} has been changed')
                file_hashes[file] = current_hash
        
        time.sleep(10)

def detect_malware():
   
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        if any(keyword in str(proc.info['cmdline']) for keyword in ['malware', 'virus']):
            print(f'Malicious process detected: {proc.info["name"]} - PID: {proc.info["pid"]}')
            send_email('Malware Detected', f'Malicious process detected: {proc.info["name"]} - PID: {proc.info["pid"]}')
            
def analyze_traffic():
   
    try:
        response = requests.get('https://example.com', timeout=10)
        if response.status_code != 200:
            print(f'Unusual HTTP response: {response.status_code}')
            send_email('Unusual Network Activity', f'Unusual HTTP response detected: {response.status_code}')
    except requests.exceptions.RequestException as e:
        print(f'Error making HTTP request: {e}')
        send_email('Network Error', f'Error making HTTP request: {e}')

def advanced_incident_management():
    
    pass

if __name__ == "__main__":
    import threading

    threading.Thread(target=monitor_auth_log).start()
    threading.Thread(target=monitor_network).start()
    threading.Thread(target=monitor_critical_files).start()
    threading.Thread(target=detect_malware).start()
    threading.Thread(target=analyze_traffic).start()
    threading.Thread(target=advanced_incident_management).start()
