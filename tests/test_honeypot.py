import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import honeypot
from fake_filesystem import FAKE_FS, FILE_CONTENTS


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
