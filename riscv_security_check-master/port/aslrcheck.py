import helpers


def aslrcheck():
    # PaX ASLR support
    if helpers.get_exitcode("grep -q 'Name:' /proc/1/status 2> /dev/null"):
        print('\033[33m insufficient privileges for PaX ASLR checks\033[m')
        print('  Fallback to standard Linux ASLR check')

    if not helpers.get_exitcode("grep -q 'PaX:' /proc/1/status 2> /dev/null"):
        if not helpers.get_exitcode(
            "grep -q 'PaX:' /proc/1/status 2> /dev/null | grep -q 'R'"
        ):
            print('\033[32mPaX ASLR enabled\033[m\n')
        else:
            print('\033[31mPaX ASLR disabled\033[m\n')
    else:
        print(" (kernel.randomize_va_space): ", end="")
        # standard Linux 'kernel.randomize_va_space' ASLR support
        sysctl_output = helpers.get_stdout('sysctl -a 2> /dev/null')
        if 'kernel.randomize_va_space = 1' in sysctl_output:
            print('\033[33mPartial (Setting: 1)\033[m\n')
            print(
                "  Description - Make the addresses of mmap base, stack and VDSO page randomized.\n"
                "  This, among other things, implies that shared libraries will be loaded to \n"
                "  random addresses. Also for PIE-linked binaries, the location of code start\n"
                "  is randomized. Heap addresses are *not* randomized.\n"
            )
        elif 'kernel.randomize_va_space = 2' in sysctl_output:
            print('\033[32mFull (Setting: 2)\033[m\n')
            print(
                "  Description - Make the addresses of mmap base, heap, stack and VDSO page randomized.\n"
                "  This, among other things, implies that shared libraries will be loaded to random \n"
                "  addresses. Also for PIE-linked binaries, the location of code start is randomized.\n"
            )
        elif 'kernel.randomize_va_space = 0' in sysctl_output:
            print('\033[31mNone (Setting: 0)\033[m')
        else:
            print('\033[31mNot supported\033[m')
        print(
            "  See the kernel file 'Documentation/admin-guide/sysctl/kernel.rst' for more details.\n"
        )
