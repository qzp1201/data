import os
import shlex

import filecheck
import helpers


def chk_dir(dir: str):
    if not dir:
        print("\033[31mError: Please provide a valid directory.\033[m\n")
        assert False

    if not os.path.isdir(dir):
        print("\033[31mError: The directory '%s' does not exist.\033[m\n")
        assert False

    # follow symlink
    # remove trailing slashes
    dir = os.path.realpath(dir)

    for root, _, files in os.walk(dir):
        for file in files:
            file = os.path.join(root, file)

            if not os.access(file, os.R_OK):
                # print(
                #     "\033[31mError: No read permissions for '%s' (run as root).\033[m"
                # )
                continue

            file_output = helpers.get_stdout(
                'file ' + shlex.quote(os.path.realpath(file))
            )
            if 'ELF' not in file_output:
                # print(
                #     "\033[31mError: Not an ELF file: " + file_output.strip() + "\033[m"
                # )
                continue

            filecheck.filecheck(file)
            if os.stat(file).st_mode & 0o6000:
                print(f"\033[37;41m{file}\033[m")
            else:
                print(file)
