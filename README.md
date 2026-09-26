# Honeypot++

Honeypot++ is a low-interaction SSH deception system designed for cybersecurity labs, SOC training, and DFIR research. It emulates a real SSH service, captures attacker credentials and commands, and logs behavior for analysis. All in a safe, controlled environment.

## Features
- Realistic low‑interaction SSH honeypot
- Persistent SSH host key & spoofed OpenSSH banner
- Realistic OS‑based fingerprinting in uname & login banner
- Human‑like per‑command timing delays
- Credential harvesting & full command logging
- Interactive fake shell with virtual filesystem
- Safe, fully emulated (no real command execution)
- Session classification (reconnaissance / payload delivery / bruteforce) attached to every logged session

## Tech Stack
- Python 3
- Paramiko
- Socket & threading

## Usage
Run the honeypot:
```bash
python honeypot.py
```

## Tests
```bash
python3 -m unittest discover tests
```

Nine tests cover the fake shell command handler: cat, cd, pwd, whoami, an unknown command, and a missing or empty command. Five more cover session classification (payload delivery, reconnaissance, bruteforce/automation, and an ordinary short session).
