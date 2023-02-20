#! /usr/bin/env python3

import errno
import os
import socket
import subprocess
import seccomp

if __name__ == "__main__":
    f = seccomp.SyscallFilter(seccomp.ALLOW)

    # Disable opening IPv4/IPv6 network sockets on the child process
    if os.getenv("SECCOMP_BLOCK_IP") == "true":
        f.add_rule(
            seccomp.ERRNO(errno.EACCES),
            "socket",
            seccomp.Arg(0, seccomp.EQ, socket.AF_INET),
        )
        f.add_rule(
            seccomp.ERRNO(errno.EACCES),
            "socket",
            seccomp.Arg(0, seccomp.EQ, socket.AF_INET6),
        )

    # Prevent student submissions from using inotify events
    # to modify `results.json` after the nonce has been added
    if os.getenv("SECCOMP_BLOCK_INOTIFY") == "true":
        f.add_rule(seccomp.ERRNO(errno.EACCES), "inotify_add_watch")

    f.load()

    # Transparently run the actual grader code
    with open("/autograder/results/stdout", "w") as stdoutf:
        p = subprocess.Popen(
            "./run_autograder",
            cwd="/autograder",
            stdout=stdoutf,
            stderr=subprocess.STDOUT,
        )
        p.wait()
