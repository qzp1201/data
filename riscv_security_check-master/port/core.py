import os
import helpers


def search_libc():
    # TODO: LIBC_SEARCH_PATH
    path = helpers.get_stdout(
        "ldconfig -p | grep 'libc\.so' | awk '{print $4}' | head -n 1"
    ).strip()
    if os.path.isfile(path):
        return path

    path = helpers.get_stdout(
        'find /lib/ /lib64/ / \\( -name "libc.so.6" -o -name "libc.so.7" -o -name "libc.so" \\) -print -quit 2> /dev/null'
    ).strip()
    if os.path.isfile(path):
        return path

    print("\033[31mError: libc not found.\033[m\n")
    assert False
