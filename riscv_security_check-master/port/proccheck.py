import shlex
import core
import helpers


def proccheck(pid: int):
    readelf_l = helpers.get_stdout(f"readelf -W -l /proc/{pid}/exe 2> /dev/null")
    if "Program Headers" in readelf_l:
        if "GNU_RELRO" in readelf_l:
            readelf_d = helpers.get_stdout(
                f"readelf -W -l /proc/{pid}/exe 2> /dev/null"
            )
            if "BIND_NOW" in readelf_d or '.got.plt' not in readelf_l:
                print("\033[32mFull RELRO   \033[m   ", end="")
            else:
                print("\033[33mPartial RELRO\033[m   ", end="")
        else:
            print("\033[31mNo RELRO     \033[m   ", end="")
    else:
        print("\033[31mPermission denied (please run as root)\033[m")
        assert False

    readelf_s = helpers.get_stdout(f"readelf -W -s /proc/{pid}/exe 2> /dev/null")
    if "Symbol table" in readelf_s:
        canary = False
        for line in readelf_s.splitlines():
            if (
                "__stack_chk_fail" in line
                or "__stack_chk_guard" in line
                or "__intel_security_cookie" in line
            ) and " UND " in line:
                canary = True
                break
        # canary = (
        #     "__stack_chk_fail" in readelf_s
        #     or "__stack_chk_guard" in readelf_s
        #     or "__intel_security_cookie" in readelf_s
        # )
        if canary:
            print("\033[32mCanary found         \033[m   ", end="")
        else:
            print("\033[31mNo canary found      \033[m   ", end="")
    else:
        print("\033[33mNo symbol table found \033[m  ", end="")

    # TODO: Clang CFI

    with open(f"/proc/{pid}/status", "r") as f:
        status = f.read()
    seccomp = helpers.grep_first(status, "Seccomp:")
    if seccomp and len(seccomp) > 9:
        seccomp = seccomp[9]
    if seccomp == '1':
        print("\033[32mSeccomp strict\033[m   ", end="")
    elif seccomp == '2':
        print("\033[32mSeccomp-bpf   \033[m   ", end="")
    else:
        print("\033[31mNo Seccomp    \033[m   ", end="")

    pax = helpers.grep_first(status, "PaX:")
    if pax and len(pax) > 9:
        pageexec = pax[5]
        segmexec = pax[9]
        mprotect = pax[7]
        randmmap = pax[8]
        if (pageexec == "P" or segmexec == "S") and mprotect == "M" and randmmap == "R":
            print('\033[32mPaX enabled\033[m   ', end="")
        elif pageexec == "p" and segmexec == "s" and randmmap == "R":
            print('\033[33mPaX ASLR only\033[m ', end="")
        elif (
            (pageexec == "P" or segmexec == "S") and mprotect == "m" and randmmap == "R"
        ):
            print('\033[33mPaX mprot off \033[m', end="")
        elif (
            (pageexec == "P" or segmexec == "S") and mprotect == "M" and randmmap == "r"
        ):
            print('\033[33mPaX ASLR off\033[m  ', end="")
        elif (
            (pageexec == "P" or segmexec == "S") and mprotect == "m" and randmmap == "r"
        ):
            print('\033[33mPaX NX only\033[m   ', end="")
        else:
            print('\033[31mPaX disabled\033[m  ', end="")
    elif (
        helpers.get_stdout(
            f"readelf -W -l /proc/{pid}/exe 2> /dev/null | grep 'GNU_STACK' | grep -oP '(?<=0x).*(?=RW )' | grep -o . | sort -u | tr -d '\n'"
        ).strip()
        != "0x"
    ):
        print("\033[31mNX disabled\033[m   ", end="")
    else:
        print("\033[32mNX enabled \033[m   ", end="")

    if not helpers.get_exitcode(
        f"readelf -h /proc/{pid}/exe 2> /dev/null | grep -q 'Type:[[:space:]]*EXEC'"
    ):
        print("\033[31mNo PIE               \033[m   ", end="")
    elif not helpers.get_exitcode(
        f"readelf -h /proc/{pid}/exe 2> /dev/null | grep -q 'Type:[[:space:]]*DYN'"
    ):
        if not helpers.get_exitcode(
            f"readelf -d /proc/{pid}/exe 2> /dev/null | grep -q 'DEBUG'"
        ):
            print("\033[32mPIE enabled          \033[m   ", end="")
        else:
            print("\033[33mDynamic Shared Object\033[m   ", end="")
    else:
        print("\033[33mNot an ELF file      \033[m   ", end="")

    # TODO: selfrando

    if not helpers.get_exitcode(
        f'readelf -W -d "$(readlink /proc/{pid}/exe)" 2> /dev/null'
        + " | grep 'NEEDED' | grep -q 'libc\.so'"
    ):
        FS_libc = core.search_libc()
        Proc_FS_filechk_func_libc = helpers.get_stdout(
            f"readelf -W -s --use-dynamic {shlex.quote(FS_libc)} 2> /dev/null | sed -ne 's/.*__\\(.*_chk\\)@@.*/\\1/p'"
        ).splitlines()
        assert all(map(lambda x: x.endswith('_chk'), Proc_FS_filechk_func_libc))
        Proc_FS_func_libc = list(map(lambda x: x[:-4], Proc_FS_filechk_func_libc))
        Proc_FS_func = helpers.get_stdout(
            f"readelf -W -s --use-dynamic /proc/{pid}/exe 2> /dev/null | awk '{{ print $8 }}' | sed -e 's/_*//' -e 's/@.*//' -e '/^$/d'"
        ).splitlines()
        # Proc_FS_cnt_checked = helpers.get_stdout(
        #     f'grep -cFxf <(sort -u <<< "{Proc_FS_filechk_func_libc}") <(sort -u <<< "{Proc_FS_func}")'
        # )
        # Proc_FS_cnt_unchecked = helpers.get_stdout(
        #     f'grep -cFxf <(sort -u <<< "{Proc_FS_func_libc}") <(sort -u <<< "{Proc_FS_func}")'
        # )
        Proc_FS_filechk_func_libc = set(Proc_FS_filechk_func_libc)
        Proc_FS_func_libc = set(Proc_FS_func_libc)
        Proc_FS_func = set(Proc_FS_func)
        Proc_FS_cnt_checked = len(Proc_FS_filechk_func_libc.intersection(Proc_FS_func))
        Proc_FS_cnt_unchecked = len(Proc_FS_func_libc.intersection(Proc_FS_func))
        Proc_FS_cnt_total = Proc_FS_cnt_unchecked + Proc_FS_cnt_checked
        if not Proc_FS_cnt_total:
            print("\033[32mN/A\033[m", end="")
        elif not Proc_FS_cnt_checked:
            print("\033[31mNo\033[m", end="")
        else:
            print('\033[32mYes\033[m', end="")
    else:
        print("\033[32mN/A\033[m", end="")
