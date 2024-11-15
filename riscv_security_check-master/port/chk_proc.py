import os
import aslrcheck
import coredumpcheck
import helpers
import nxcheck
import proccheck


def chk_proc_all():
    print("* System-wide ASLR", end="")
    aslrcheck.aslrcheck()
    print("* Does the CPU support NX: ", end="")
    nxcheck.nxcheck()
    print("* Core-Dumps access to all users: ", end="")
    coredumpcheck.coredumpcheck()

    # TODO: extended_checks
    print(
        "         COMMAND    PID RELRO           STACK CANARY            SECCOMP          NX/PaX        PIE                     FORTIFY"
    )

    mypid = os.getpid()
    lastpid = 0
    for dir in os.listdir('/proc'):
        if not dir.isnumeric() or int(dir) == mypid:
            continue
        try:
            os.readlink(f"/proc/{dir}/exe")
            lastpid += 1
        except:
            continue

    currpid = 0
    for dir in os.listdir('/proc'):
        if not dir.isnumeric() or int(dir) == mypid:
            continue
        try:
            os.readlink(f"/proc/{dir}/exe")
            currpid += 1
        except:
            continue

        name = helpers.get_stdout(f"head -1 /proc/{dir}/status | cut -b 7-").strip()
        print("%16s" % name, end="")
        print("%7d " % int(dir), end="")
        proccheck.proccheck(int(dir))
        print()

    if os.getuid() != 0:
        print(
            "\n\033[33mNote: You are running 'checksec.sh' as an unprivileged user.\n"
            "      Too see all processes, please run the script as root.\033[m\n"
        )
