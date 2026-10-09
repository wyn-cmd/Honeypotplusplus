def classify(commands):
    # Return unknown if no commands are provided
    if not commands:
        return "unknown"
    # Large number of commands indicates automation
    if len(commands) > 10:
        return "bruteforce_or_automation"
    # Tools used for downloading or network communication
    tools = ("wget", "curl", "nc")
    # Identify payload delivery based on tool usage
    if any(tool in cmd for cmd in commands for tool in tools):
        return "payload_delivery"
    # Common commands used for system reconnaissance
    markers = ("cat /etc/passwd", "whoami", "uname")
    # Identify reconnaissance based on marker usage
    if any(marker in cmd for cmd in commands for marker in markers):
        return "reconnaissance"
    return "unknown"
