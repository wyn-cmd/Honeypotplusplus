def classify(commands):
    if len(commands) > 10:
        return "bruteforce_or_automation"
    if any(tool in cmd for cmd in commands for tool in ["wget", "curl", "nc"]):
        return "payload_delivery"
    if any(marker in cmd for cmd in commands for marker in ["cat /etc/passwd", "whoami", "uname"]):
        return "reconnaissance"
    return "unknown"