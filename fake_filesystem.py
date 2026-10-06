# fake_filesystem.py

# Fake directory structure
# Maps each directory path to a list of its contained items
# Ensure all directories have corresponding entries to avoid lookup failures
FAKE_FS = {
    "/": ["bin", "etc", "home", "var"],
    "/bin": [],
    "/home": ["admin"],
    "/home/admin": ["notes.txt", ".bash_history"],
    "/etc": ["passwd", "shadow"],
    "/var": []
}

# Fake file contents
# Maps each file path to its string content
FILE_CONTENTS = {
    "/home/admin/notes.txt": "TODO: rotate SSH keys",
    "/home/admin/.bash_history": "ls\ncd /etc\ncat shadow\n",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash",
    "/etc/shadow": "Permission denied"
}