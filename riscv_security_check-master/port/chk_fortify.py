import os
import shlex

import core
import fs_funcs
import helpers


def chk_fortify_file(file: str):
    if not file:
        print("\033[31mError: Please provide a valid file.\033[m\n")
        assert False

    if file[0] == '~':
        file = os.path.expanduser(file)

    # Does the file exist?
    if not os.access(file, os.F_OK):
        print(f"\033[31mError: The file '{file}' does not exist.\033[m\n")
        assert False

    # Read permissions?
    if not os.access(file, os.R_OK):
        print(f"\033[31mError: No read permissions for '{file}' (run as root).\033[m\n")
        assert False

    # ELF executable?
    file_output = helpers.get_stdout('file ' + shlex.quote(os.path.realpath(file)))
    if 'ELF' not in file_output:
        print("\033[31mError: Not an ELF file: " + file_output.strip() + "\033[m")
        assert False

    fs_libc = core.search_libc()
    fs_chk_func_libc = helpers.get_stdout(
        f"readelf -W -s {shlex.quote(fs_libc)} 2> /dev/null | grep _chk@@ | awk '{{ print $8 }}' | cut -c 3- | sed -e 's/_chk@.*//' | sort -u"
    ).splitlines()
    fs_functions = helpers.get_stdout(
        f"readelf -W -s {shlex.quote(file)} 2> /dev/null | awk '{{ print $8 }}' | sed 's/_*//' | sed -e 's/@.*//' | sort -u"
    ).splitlines()

    fs_funcs.fs_libc_check(fs_chk_func_libc)
    fs_funcs.fs_binary_check(fs_functions)
    fs_cnt_checked, fs_cnt_unchecked = fs_funcs.fs_comparison(
        fs_functions, fs_chk_func_libc
    )
    fs_funcs.fs_summary(
        fs_functions, fs_chk_func_libc, fs_cnt_checked, fs_cnt_unchecked
    )
