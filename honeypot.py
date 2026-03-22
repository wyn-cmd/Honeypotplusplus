# =========================
# Honeypot++ SSH Deception System
# =========================
# This program implements a low-interaction SSH honeypot using Paramiko.
# It accepts all credentials, emulates basic shell commands, and logs
# attacker behavior (credentials + commands) for analysis.
#
# IMPORTANT:
# - Deploy ONLY in isolated lab environments
# - Do NOT expose to production or the public internet
# =========================




import socket
import threading
import json
import time
import os
import random
import platform
import paramiko

from concurrent.futures import ThreadPoolExecutor
from fake_filesystem import FAKE_FS, FILE_CONTENTS
from profiles import classify


# Generate a temporary RSA host key for the SSH server
HOST = "0.0.0.0"
PORT = 2222
HOST_KEY_PATH = "ssh_host_rsa.key"


OS_NAME = os.name                    
SYSTEM = platform.system()     
NODE = platform.node()                  # hostname
RELEASE = platform.release()  
VERSION = platform.version()
MACHINE = platform.machine()  
PROCESSOR = platform.processor()


executor = ThreadPoolExecutor(max_workers=50)


UNAME_A = f"{SYSTEM} {NODE} {RELEASE} {VERSION} {MACHINE}"

def load_or_create_host_key(path):
    # Load an existing SSH host key if present.
    # Otherwise, generate and store a new one.

    if os.path.exists(path):
        return paramiko.RSAKey(filename=path)

    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    return key

HOST_KEY = load_or_create_host_key(HOST_KEY_PATH)

# Log file where attacker activity is stored
LOG_FILE = "logs/honeypot.log"

# Ensure the logs directory exists
os.makedirs("logs", exist_ok=True)



# SSH Server Interface

# defines how the SSH server behaves during authentication & session setup. It subclasses Paramiko's ServerInterface.
class HoneypotSSH(paramiko.ServerInterface):
    def __init__(self, addr):
        self.addr = addr
        self.event = threading.Event()
        self.commands = []
        self.cwd = "/"  # current working directory
        

    # Accept ANY username/password
    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        return paramiko.AUTH_SUCCESSFUL  # accept everything
    
    # Only allow password authentication
    def get_allowed_auths(self, username):
        return "password"
    
    # Allow only session channels (no port forwarding, etc.)
    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    # Allow an interactive shell
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True


def command_delay(cmd):
    # Simulate human reaction + system processing time.
    
    base_delay = random.uniform(0.08, 0.15)   # thinking time
    length_delay = min(len(cmd) * 0.0051, 0.15)  # longer commands will create longer delay
    jitter = random.uniform(0.02, 0.1)

    time.sleep(base_delay + length_delay + jitter)



# Writes attacker activity as JSON (SIEM-friendly)
log_lock = threading.Lock()

def log_event(data):
    with log_lock:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(data, separators=(",", ":")) + "\n")


# Handles a single SSH connection from start to finish
def handle_connection(client, addr):
    # Wrap raw socket in a Paramiko SSH transport
    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)

    # create a new SSH server instance
    server = HoneypotSSH(addr)

    # start SSH negotiation (key exchange, encryption, auth)
    try:
        transport.start_server(server=server)
    except paramiko.SSHException:
        return

    # accept SSH channel
    chan = transport.accept(20)
    if chan is None:
        return

    # wait for shell request to be confirmed
    server.event.wait(10)
    banner = (
    f"Welcome to {SYSTEM} {RELEASE} ({MACHINE})\n"
    f"Last login: {time.ctime()} from {addr[0]}\n"
    "$ "
    )

    chan.send(banner.encode())

    while True:
        try:

            # Receive encrypted command data
            chan.settimeout(300)

            try:
                cmd = chan.recv(1024)
            except socket.timeout:
                break
            if not cmd:
                break

            # decode safely (ignore binary/control chars)
            cmd = cmd.decode(errors="ignore").strip()
            server.commands.append(cmd)

            # generate fake command output
            command_delay(cmd) 

            response = emulate_command(cmd, server)


            # Send output back to attacker
            chan.send(response.encode() + b"\n$ ")

        except Exception:
            break

    # Log full attacker session
    log_event({
        "timestamp": time.time(),
        "source_ip": addr[0],
        "username": server.username,
        "password": server.password,
        "commands": server.commands
    })


    # clean up connection
    chan.close()
    transport.close()



# provides believable but harmless responses to common commands
def emulate_command(cmd, server=None):
    parts = cmd.split()

    if not parts:
        return ""


    # Basic identity commands
    if cmd == "whoami":
        return "root"

    if cmd == "id":
        return f"uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:unconfined_t:s0"


    if parts[0] == "uname":
        if "-a" in parts:
            return UNAME_A
        return SYSTEM

    # Directory handling
    if parts[0] == "pwd":
        return server.cwd

    if parts[0] == "cd":
        target = parts[1] if len(parts) > 1 else "/"

        if target == "..":
            server.cwd = "/".join(server.cwd.rstrip("/").split("/")[:-1]) or "/"
            return ""

        if target.startswith("/"):
            if target in FAKE_FS:
                server.cwd = target
                return ""
        else:
            new_path = f"{server.cwd.rstrip('/')}/{target}"
            if new_path in FAKE_FS:
                server.cwd = new_path
                return ""

        return f"bash: cd: {target}: No such file or directory"


    # File listing
    if parts[0] == "ls":
        path = server.cwd if len(parts) == 1 else parts[1]
        return "  ".join(FAKE_FS.get(path, []))


    # File reading
    if parts[0] == "cat":
        if len(parts) < 2:
            return "cat: missing file operand"

        file_path = parts[1]
        if not file_path.startswith("/"):
            file_path = f"{server.cwd.rstrip('/')}/{file_path}"

        return FAKE_FILES.get(file_path, "Permission denied")


    # Echo
    if parts[0] == "echo":
        return " ".join(parts[1:])


    # Process / network info
    if cmd == "ps":
        return (
            "PID TTY      TIME CMD\n"
            "1   ?        00:00 init\n"
            "1337 pts/0   00:00 bash\n"
        )

    if cmd in ("ifconfig", "ip a"):
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING>\n"
            "inet 10.0.0.10 netmask 255.255.255.0\n"
        )


    # History
    if cmd == "history":
        return "\n".join(
            f"{i+1}  {c}" for i, c in enumerate(server.commands)
        )


    # Exit
    if cmd in ("exit", "logout"):
        return "logout"

    return "command not found"



# creates a TCP listener and spawns a thread per connection
def start_honeypot():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", 2222))
    sock.listen(100)

    print("[+] SSH Honeypot++ listening on port 2222")

    while True:
        client, addr = sock.accept()
        executor.submit(handle_connection, client, addr)


if __name__ == "__main__":
    start_honeypot()
