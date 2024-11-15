import os
import subprocess


def get_stdout(cmd: str) -> str:
    with os.popen(cmd, 'r') as proc:
        return proc.read()


def command_exists(cmd: str) -> bool:
    result = get_stdout("type " + cmd)
    if "not found" in result:
        return False
    if "is" in result:
        return True
    assert False, result


def get_exitcode(cmd: str) -> int:
    proc = subprocess.run(cmd, shell=True)
    return proc.returncode


def grep_first(haystack: str, needle: str) -> str:
    for line in haystack.splitlines():
        if needle in line:
            return needle
    return None
