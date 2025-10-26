#!/var/ossec/framework/python/bin/python3
# Copyright (C) Wazuh Inc.
# Wazuh - VirusTotal integration

import sys
import json
import requests
import hashlib
from socket import socket, AF_UNIX, SOCK_DGRAM

QUEUE_SOCKET = "/var/ossec/queue/sockets/queue"

def send_event(msg):
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(QUEUE_SOCKET)
        sock.send(msg.encode())
        sock.close()
    except Exception as e:
        print(f"[Error] Cannot send event to queue: {e}")

def virustotal_lookup(api_key, file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            positives = stats["malicious"] + stats["suspicious"]
            total = sum(stats.values())
            return positives, total
        elif r.status_code == 404:
            print("[VT] File not found on VirusTotal.")
            return None, None
        else:
            print(f"[VT] Error {r.status_code}: {r.text}")
            return None, None
    except Exception as e:
        print(f"[VT] Lookup error: {e}")
        return None, None

def sha256_file(filename):
    sha256 = hashlib.sha256()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def main():
    if "-k" not in sys.argv or "-f" not in sys.argv:
        print("Usage: virustotal -k <api_key> -f <file>")
        sys.exit(1)

    api_key = sys.argv[sys.argv.index("-k") + 1]
    filename = sys.argv[sys.argv.index("-f") + 1]
    file_hash = sha256_file(filename)
    positives, total = virustotal_lookup(api_key, file_hash)

    if positives is not None:
        msg = json.dumps({
            "integration": "virustotal",
            "file": filename,
            "sha256": file_hash,
            "positives": positives,
            "total": total
        })
        send_event(msg)
        print(f"✅ {filename}: {positives}/{total} detections on VirusTotal.")
    else:
        print(f"❌ {filename}: lookup failed or not found.")

if __name__ == "__main__":
    main()
