import os
import shlex

import core
import helpers


def filecheck(file: str):
    # check for RELRO support
    quoted_file = shlex.quote(file)
    readelf_l = helpers.get_stdout('readelf -W -l ' + quoted_file)
    readelf_d = helpers.get_stdout('readelf -d ' + quoted_file)

    if "no program headers" in readelf_l:
        print('\033[32mN/A          \033[m   ', end='')
    elif 'GNU_RELRO' in readelf_l:

        if 'BIND_NOW' in readelf_d or '.got.plt' not in readelf_l:
            print('\033[32mFull RELRO   \033[m   ', end='')
        else:
            print('\033[33mPartial RELRO\033[m   ', end='')
    else:
        print('\033[31mNo RELRO     \033[m   ', end='')

    # fallback on dynamic section to retrieve symbols when symbol table is unavailable
    readelf_syms = 'readelf -W -s '
    if "Dynamic symbol information is not available" in helpers.get_stdout(
        readelf_syms + quoted_file
    ):
        readelf_syms += '--use-dynamic '
    readelf_s = helpers.get_stdout(readelf_syms + quoted_file)

    # check for stack canary support
    canary = False
    for line in readelf_s.splitlines():
        if (
            "__stack_chk_fail" in line
            or "__stack_chk_guard" in line
            or "__intel_security_cookie" in line
        ) and " UND " in line:
            canary = True
            break
    if canary:
        print('\033[32mCanary found   \033[m   ', end='')
    else:
        print('\033[31mNo canary found\033[m   ', end='')

    # check for NX support
    if "no program headers" in readelf_l:
        print('\033[32mN/A        \033[m   ', end='')
    elif 'GNU_STACK' in readelf_l:
        if (
            helpers.get_stdout(
                f"readelf -W -l {quoted_file} 2> /dev/null | grep 'GNU_STACK' | grep -oP '(?<=0x).*(?=RW )' | grep -o . | sort -u | tr -d '\n'"
            ).strip()
            != "0x"
        ):
            print('\033[31mNX disabled\033[m   ', end='')
        else:
            print('\033[32mNX enabled \033[m   ', end='')
    else:
        print('\033[31mNX disabled\033[m   ', end='')

    # check for PIE support
    if not helpers.get_exitcode(
        f"readelf -h {quoted_file} 2> /dev/null | grep -q 'Type:[[:space:]]*EXEC'"
    ):
        print('\033[31mNo PIE       \033[m   ', end='')
    elif not helpers.get_exitcode(
        f"readelf -h {quoted_file} 2> /dev/null | grep -q 'Type:[[:space:]]*DYN'"
    ):
        if 'DEBUG' in readelf_d:
            print('\033[32mPIE enabled  \033[m   ', end='')
        else:
            print('\033[33mDSO          \033[m   ', end='')
    elif not helpers.get_exitcode(
        f"readelf -h {quoted_file} 2> /dev/null | grep -q 'Type:[[:space:]]*REL'"
    ):
        print('\033[33mREL          \033[m   ', end='')
    else:
        print('\033[33mNot an ELF file\033[m   ', end='')

    # TODO: selfrando, Clang CFI

    # check for rpath
    if "no dynamic section" in readelf_d:
        print('\033[32mN/A      \033[m  ', end='')
    else:
        rpath_array = (
            helpers.get_stdout(
                f"readelf -d {quoted_file} | awk -F'[][]' '/RPATH/ {{print $2}}'"
            )
            .strip()
            .split(':')
        )

        if rpath_array and rpath_array[0]:
            # HACK
            rpath_array = list(
                map(
                    lambda x: os.path.normpath(x.replace('$ORIGIN', file + '/..')),
                    rpath_array,
                )
            )
            if 'rw' in helpers.get_stdout('stat -c %A ' + shlex.join(rpath_array)):
                print('\033[31mRW-RPATH \033[m  ', end='')
            else:
                print('\033[31mRPATH   \033[m  ', end='')
        else:
            print('\033[32mNo RPATH \033[m  ', end='')

    # check for runpath
    if "no dynamic section" in readelf_d:
        print('\033[32mN/A        \033[m  ', end='')
    else:
        runpath_array = (
            helpers.get_stdout(
                f"readelf -d {quoted_file} | awk -F'[][]' '/RUNPATH/ {{print $2}}'"
            )
            .strip()
            .split(':')
        )

        if runpath_array and runpath_array[0]:
            # HACK
            runpath_array = list(
                map(
                    lambda x: os.path.normpath(x.replace('$ORIGIN', file + '/..')),
                    runpath_array,
                )
            )
            if 'rw' in helpers.get_stdout('stat -c %A ' + shlex.join(runpath_array)):
                print('\033[31mRW-RUNPATH \033[m  ', end='')
            else:
                print('\033[31mRUNPATH    \033[m  ', end='')
        else:
            print('\033[32mNo RUNPATH \033[m  ', end='')

    # check for stripped symbols
    sym_cnt = helpers.get_stdout(
        f"readelf --symbols {quoted_file} 2> /dev/null | grep '\\.symtab' | cut -d' ' -f5 | cut -d: -f1"
    ).strip()
    if sym_cnt:
        print("\033[31m{} Symbols\t\033[m".format(sym_cnt), end='')
    else:
        print('\033[32mNo Symbols\t\033[m', end='')

    # additional checks
    # bugfix
    FS_cnt_checked, FS_cnt_total = 0, 0
    if not helpers.get_exitcode(
        f'readelf -d {quoted_file} 2> /dev/null'
        + " | grep 'NEEDED' | grep -q 'libc\\.so'"
    ):
        FS_libc = core.search_libc()
        FS_filechk_func_libc = helpers.get_stdout(
            f"readelf -W -s --use-dynamic {shlex.quote(FS_libc)} 2> /dev/null | sed -ne 's/.*__\\(.*_chk\\)@@.*/\\1/p'"
        ).splitlines()
        assert all(map(lambda x: x.endswith('_chk'), FS_filechk_func_libc))
        FS_func_libc = set(map(lambda x: x[:-4], FS_filechk_func_libc))
        FS_filechk_func_libc = set(FS_filechk_func_libc)
        FS_func = set(
            helpers.get_stdout(
                f"readelf -W -s --use-dynamic {quoted_file} 2> /dev/null | awk '{{ print $8 }}' | sed -e 's/_*//' -e 's/@.*//' -e '/^$/d'"
            ).splitlines()
        )
        FS_cnt_checked = len(FS_filechk_func_libc.intersection(FS_func))
        FS_cnt_unchecked = len(FS_func_libc.intersection(FS_func))
        FS_cnt_total = FS_cnt_unchecked + FS_cnt_checked
        if not FS_cnt_total:
            print("\033[32mN/A\033[m", end="")
        elif not FS_cnt_checked:
            print("\033[31mNo\033[m", end="")
        else:
            print('\033[32mYes\033[m', end="")
    else:
        print("\033[32mN/A\033[m", end="")

    print("\t{}\t".format(FS_cnt_checked), end="")
    print("\t{}\t\t".format(FS_cnt_total), end="")
