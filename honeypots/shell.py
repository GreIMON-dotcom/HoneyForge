"""Emulated Linux shell for the medium-interaction Telnet decoy.

Nothing here runs a process, opens a file or makes a network connection. Every
answer is assembled from the fixed tables below, so a visitor can explore a
plausible system while the only effect of any input is a telemetry record.
"""
import shlex

MAX_OUTPUT = 4096
KERNEL = "5.15.0-105-generic"
OS_RELEASE = ('PRETTY_NAME="Ubuntu 22.04.4 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
              'VERSION="22.04.4 LTS (Jammy Jellyfish)"\nID=ubuntu\nID_LIKE=debian\n')
PASSWD = ("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
          "bin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
          "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nsshd:x:106:65534::/run/sshd:/usr/sbin/nologin\n"
          "{user}:x:{uid}:{uid}:{user}:{home}:/bin/bash\n")
CPUINFO = ("processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n"
           "cpu MHz\t\t: 2399.998\ncache size\t: 35840 KB\ncpu cores\t: 1\nbogomips\t: 4799.99\n")
MOUNTS = ("/dev/vda1 / ext4 rw,relatime 0 0\nproc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
          "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\ntmpfs /run tmpfs rw,nosuid,nodev,mode=755 0 0\n"
          "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n")
PROCESSES = ("  PID TTY          TIME CMD\n    1 ?        00:00:03 systemd\n  412 ?        00:00:00 cron\n"
             "  538 ?        00:00:01 sshd\n  601 ?        00:00:00 inetd\n {pid} pts/0    00:00:00 bash\n {ps} pts/0    00:00:00 ps\n")
DIRECTORIES = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var"],
    "/bin": ["bash", "busybox", "cat", "ls", "sh"], "/etc": ["hostname", "hosts", "issue", "os-release", "passwd", "resolv.conf"],
    "/home": [], "/root": [], "/tmp": [], "/opt": [], "/srv": [], "/proc": ["cpuinfo", "meminfo", "mounts", "version"],
    "/var": ["backups", "log", "www"], "/var/log": ["auth.log", "syslog"], "/var/www": ["html"], "/var/www/html": ["index.html"],
    "/var/backups": [], "/usr": ["bin", "lib", "local", "sbin", "share"],
}
TRANSFER = frozenset({"wget", "curl", "tftp", "ftpget", "ftp", "scp", "nc", "ncat", "telnet", "ssh"})
SILENT = frozenset({"sh", "bash", "ash", "enable", "system", "shell", "linuxshell", "export", "unset", "set", "cd.", "true",
                    "chmod", "chown", "rm", "mkdir", "touch", "mv", "cp", "kill", "killall", "ulimit", "history", "sync", "sleep", ">"})


def severity(line: str) -> str:
    """Attempts to download or launch a payload matter more than looking around."""
    words = set(line.replace(";", " ").replace("|", " ").replace("&", " ").split())
    risky = TRANSFER | {"chmod", "busybox", "/bin/busybox", "dd", "base64", "python", "perl", "crontab"}
    return "high" if words & risky or "./" in line else "medium"


class Shell:
    def __init__(self, hostname: str, user: str):
        self.hostname, self.user = hostname, user or "root"
        self.home = "/root" if self.user == "root" else "/home/" + self.user
        self.cwd = self.home
        self.directories = {**DIRECTORIES, self.home: [".bash_history", ".profile"]}
        if self.user != "root":
            self.directories["/home"] = [self.user]
        uid = 0 if self.user == "root" else 1000
        self.identity = f"uid={uid}({self.user}) gid={uid}({self.user}) groups={uid}({self.user})"
        self.files = {
            "/etc/passwd": PASSWD.format(user=self.user, uid=uid, home=self.home) if uid else PASSWD.split("{user}")[0],
            "/etc/hostname": hostname + "\n", "/etc/os-release": OS_RELEASE, "/etc/issue": "Ubuntu 22.04.4 LTS \\n \\l\n",
            "/etc/hosts": f"127.0.0.1 localhost\n127.0.1.1 {hostname}\n", "/etc/resolv.conf": "nameserver 127.0.0.53\n",
            "/proc/cpuinfo": CPUINFO, "/proc/mounts": MOUNTS, "/proc/meminfo": "MemTotal:        2030524 kB\nMemFree:          812340 kB\n",
            "/proc/version": f"Linux version {KERNEL} (buildd@lcy02-amd64-007) (gcc 11.4.0) #115-Ubuntu SMP\n",
            "/var/www/html/index.html": "<html><body><h1>It works!</h1></body></html>\n",
            self.home + "/.profile": "# ~/.profile: executed by the command interpreter for login shells.\n",
            self.home + "/.bash_history": "", "/var/log/auth.log": "", "/var/log/syslog": "",
        }

    def prompt(self) -> str:
        place = "~" if self.cwd == self.home else self.cwd
        return f"{self.user}@{self.hostname}:{place}{'#' if self.user == 'root' else '$'} "

    def motd(self) -> str:
        return (f"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux {KERNEL} x86_64)\n\n * Documentation:  https://help.ubuntu.com\n\n"
                "Last login: Mon Oct 12 09:14:27 2026 from 10.0.0.12\n")

    def resolve(self, path: str) -> str:
        if path.startswith("~"):
            path = self.home + path[1:]
        parts = [] if path.startswith("/") else [p for p in self.cwd.split("/") if p]
        for part in path.split("/"):
            if part == "..":
                parts = parts[:-1]
            elif part and part != ".":
                parts.append(part)
        return "/" + "/".join(parts)

    def run(self, line: str) -> tuple[str, bool]:
        """Answer one input line. Returns the text to show and whether the session ends."""
        output = []
        for part in line.replace("&&", ";").replace("||", ";").split(";")[:8]:
            text, done = self.command(part.split("|")[0].strip())
            output.append(text)
            if done:
                return "".join(output)[:MAX_OUTPUT], True
        return "".join(output)[:MAX_OUTPUT], False

    def command(self, text: str) -> tuple[str, bool]:
        try:
            words = shlex.split(text, posix=True)
        except ValueError:
            words = text.split()
        if not words:
            return "", False
        name, args = words[0], words[1:]
        plain = [a for a in args if not a.startswith("-")]
        if name in ("exit", "logout", "quit"):
            return "logout\n", True
        if name in ("/bin/busybox", "busybox"):
            return (f"{args[0]}: applet not found\n" if args else "BusyBox v1.30.1 (Ubuntu 1:1.30.1-7ubuntu3) multi-call binary.\n"), False
        name = name.rsplit("/", 1)[-1]
        if name in SILENT:
            return "", False
        if name in TRANSFER:
            target = plain[0] if plain else ""
            return f"{name}: unable to resolve host address '{target[:80]}'\n" if target else f"{name}: missing URL\n", False
        handler = getattr(self, "do_" + name, None)
        if handler:
            return handler(args, plain), False
        return f"-bash: {words[0][:60]}: command not found\n", False


    def do_whoami(self, args, plain):
        return self.user + "\n"

    def do_id(self, args, plain):
        return self.identity + "\n"

    def do_pwd(self, args, plain):
        return self.cwd + "\n"

    def do_hostname(self, args, plain):
        return self.hostname + "\n"

    def do_uname(self, args, plain):
        if any("a" in a for a in args if a.startswith("-")):
            return f"Linux {self.hostname} {KERNEL} #115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n"
        return (KERNEL if "-r" in args else "x86_64" if "-m" in args else "Linux") + "\n"

    def do_echo(self, args, plain):
        return " ".join(a for a in args if a not in ("-e", "-n", "-ne", "-en")) + "\n"

    def do_cd(self, args, plain):
        target = self.resolve(plain[0] if plain else "~")
        if target not in self.directories:
            return f"-bash: cd: {(plain[0] if plain else '')[:60]}: No such file or directory\n"
        self.cwd = target
        return ""

    def do_ls(self, args, plain):
        target = self.resolve(plain[0] if plain else ".")
        if target in self.files:
            return target.rsplit("/", 1)[-1] + "\n"
        if target not in self.directories:
            return f"ls: cannot access '{(plain[0] if plain else '')[:60]}': No such file or directory\n"
        flags = "".join(a for a in args if a.startswith("-"))
        names = [n for n in self.directories[target] if "a" in flags or not n.startswith(".")]
        if "l" not in flags:
            return ("  ".join(names) + "\n") if names else ""
        rows = [f"total {4 * len(names)}"]
        for entry in names:
            path = target.rstrip("/") + "/" + entry
            kind = "d" if path in self.directories else "-"
            rows.append(f"{kind}rw{'x' if kind == 'd' else '-'}r-xr-x 1 root root {4096 if kind == 'd' else len(self.files.get(path, '')):>5} Oct 12 09:10 {entry}")
        return "\n".join(rows) + "\n"

    def do_cat(self, args, plain):
        if not plain:
            return ""
        output = []
        for name in plain[:4]:
            path = self.resolve(name)
            if path in self.files:
                output.append(self.files[path])
            elif path in self.directories:
                output.append(f"cat: {name[:60]}: Is a directory\n")
            else:
                output.append(f"cat: {name[:60]}: No such file or directory\n")
        return "".join(output)

    def do_ps(self, args, plain):
        return PROCESSES.format(pid=1873, ps=1921)

    def do_uptime(self, args, plain):
        return " 09:14:31 up 41 days,  3:02,  1 user,  load average: 0.08, 0.03, 0.01\n"

    def do_w(self, args, plain):
        return self.do_uptime(args, plain) + f"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n{self.user:<8} pts/0    10.0.0.12        09:14    0.00s  0.02s  0.00s w\n"

    def do_free(self, args, plain):
        return ("               total        used        free      shared  buff/cache   available\n"
                "Mem:         2030524      402316      812340        1024      815868     1456208\nSwap:              0           0           0\n")

    def do_df(self, args, plain):
        return "Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/vda1       20134592 4312896  14776320  23% /\ntmpfs            1015260       0   1015260   0% /tmp\n"

    def do_nproc(self, args, plain):
        return "1\n"

    def do_date(self, args, plain):
        return "Mon Oct 12 09:14:33 UTC 2026\n"

    def do_ifconfig(self, args, plain):
        return ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.0.15  netmask 255.255.255.0  broadcast 10.0.0.255\n"
                "        ether 52:54:00:4a:1c:9e  txqueuelen 1000  (Ethernet)\n")

    def do_ip(self, args, plain):
        return "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.0.0.15/24 brd 10.0.0.255 scope global eth0\n"

    def do_which(self, args, plain):
        return "".join(f"/usr/bin/{name[:40]}\n" for name in plain[:4] if name in ("ls", "cat", "sh", "bash", "wget", "curl", "busybox"))

    def do_help(self, args, plain):
        return "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\nThese shell commands are defined internally.\n"
