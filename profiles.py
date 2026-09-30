def classify(commands):
    if not commands:
        return "unknown"
    if len(commands) > 10:
        return "bruteforce_or_automation"
    tools = ("wget", "curl", "nc")
    if any(tool in cmd for cmd in commands for tool in tools):
        return "payload_delivery"
    markers = ("cat /etc/passwd", "whoami", "uname")
    if any(marker in cmd for cmd in commands for marker in markers):
        return "reconnaissance"
    return "unknown"