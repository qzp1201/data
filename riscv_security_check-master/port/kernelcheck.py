import os
import helpers


def chk_kernel(kconfig_path: str | None = None):
    if kconfig_path:
        if os.access(kconfig_path, os.F_OK):
            kconfig_path = os.path.realpath(kconfig_path)
            print(f"* Kernel protection information for : {kconfig_path} \n")
            kernelcheck(kconfig_path)
        else:
            print("Error: config file specified do not exist")
            assert False
    else:
        print("* Kernel protection information:\n")
        kernelcheck()


def getsestatus():
    # bugfix
    status = 0
    if helpers.command_exists('getenforce'):
        sestatus = helpers.get_stdout('getenforce').strip()
        if sestatus == "Disabled":
            status = 0
        elif sestatus == "Permissive":
            status = 1
        elif sestatus == "Enforcing":
            status = 2
    elif helpers.command_exists('sestatus'):
        sestatus = helpers.get_stdout(
            "sestatus | grep 'SELinux status' | awk '{ print $3 }'"
        ).strip()
        if sestatus == "disabled":
            status = 0
        elif sestatus == "enabled":
            sestatus2 = helpers.get_stdout(
                "sestatus | grep 'Current' | awk '{ print $3 }')"
            ).strip()
            if sestatus2 == "permissive":
                status = 1
            elif sestatus2 == "enforcing":
                status = 2
    return status


def kernelcheck(kconfig_path: str | None = None):
    print(
        "  Description - List the status of kernel protection mechanisms. Rather than"
    )
    print(
        "  inspect kernel mechanisms that may aid in the prevention of exploitation of"
    )
    print("  userspace processes, this option lists the status of kernel configuration")
    print("  options that harden the kernel itself against attack.\n")
    print("  Kernel config:")

    kconfig_path_2 = '/boot/config-' + os.uname().release
    kconfig_path_3 = (os.getenv('KBUILD_OUTPUT') or '/usr/src/linux') + '/.config'
    if kconfig_path:
        print(
            f"  Warning: The config {kconfig_path} on disk may not represent running kernel config!\n"
        )
        with open(kconfig_path, 'r') as f:
            kconfig = f.read()
    elif os.access('/proc/config.gz', os.F_OK):
        kconfig = helpers.get_stdout('zcat /proc/config.gz')
        print("\033[32m    /proc/config.gz\033[m\n")
    elif os.access(kconfig_path_2, os.F_OK):
        with open(kconfig_path_2, 'r') as f:
            kconfig = f.read()
        print(f"\033[33m    {kconfig_path_2}\033[m\n")
    elif os.access(kconfig_path_3, os.F_OK):
        with open(kconfig_path_3, 'r') as f:
            kconfig = f.read()
        print(f"\033[33m    {kconfig_path_3}\033[m\n")
        print(
            "  Warning: The config on disk may not represent running kernel config!\n"
        )
    else:
        print("\033[31mNOT FOUND\033[m\n")
        assert False

    # bugfix
    if 'CONFIG_ARM=y' in kconfig:
        arch = 'arm'
    elif 'CONFIG_ARM64=y' in kconfig:
        arch = 'aarch64'
    elif 'CONFIG_X86_64=y' in kconfig:
        arch = '64'
    elif 'CONFIG_X86_32=y' in kconfig:
        arch = '32'
    elif 'CONFIG_RISCV=y' in kconfig:
        arch = 'riscv'

    print("  Vanilla Kernel ASLR:                    ", end="")
    randomize_va = helpers.get_stdout('sysctl -n kernel.randomize_va_space').strip()
    if randomize_va == "2":
        print("\033[32mFull\033[m")
    elif randomize_va == "1":
        print("\033[33mPartial\033[m")
    else:
        print("\033[31mNone\033[m")

    print("  NX protection:                          ", end="")
    cmd = None
    if helpers.command_exists("journalctl"):
        cmd = "journalctl -kb -o cat | grep -Fw NX | head -n 1"
    elif helpers.command_exists("dmesg"):
        cmd = "dmesg -t 2> /dev/null | grep -Fw NX"
    nx_protection = helpers.get_stdout(cmd).strip()
    if nx_protection:
        if nx_protection == "NX (Execute Disable) protection: active":
            print("\033[32mEnabled\033[m")
        else:
            print("\033[31mDisabled\033[m")
    else:
        print("\033[33mSkipped\033[m")

    print("  Protected symlinks:                     ", end="")
    symlink = helpers.get_stdout('sysctl -n fs.protected_symlinks').strip()
    if symlink == "1":
        print("\033[32mEnabled\033[m")
    else:
        print("\033[31mDisabled\033[m")

    print("  Protected hardlinks:                    ", end="")
    hardlink = helpers.get_stdout('sysctl -n fs.protected_hardlinks').strip()
    if hardlink == "1":
        print("\033[32mEnabled\033[m")
    else:
        print("\033[31mDisabled\033[m")

    print("  Protected fifos:                        ", end="")
    fifos = helpers.get_stdout('sysctl -n fs.protected_fifos').strip()
    if not fifos:
        print("\033[33mUnsupported\033[m")
    elif fifos == "1":
        print("\033[33mPartial\033[m")
    elif fifos == "2":
        print("\033[32mEnabled\033[m")
    else:
        print("\033[31mDisabled\033[m")

    print("  Protected regular:                      ", end="")
    regular = helpers.get_stdout('sysctl -n fs.protected_regular').strip()
    if not regular:
        print("\033[33mUnsupported\033[m")
    elif regular == "1":
        print("\033[33mPartial\033[m")
    elif regular == "2":
        print("\033[32mEnabled\033[m")
    else:
        print("\033[31mDisabled\033[m")

    print("  Ipv4 reverse path filtering:            ", end="")
    ipv4_rpath = helpers.get_stdout('sysctl -n net.ipv4.conf.all.rp_filter').strip()
    if ipv4_rpath == "1":
        print("\033[32mEnabled\033[m")
    else:
        print("\033[31mDisabled\033[m")

    print("  Kernel heap randomization:              ", end="")
    # NOTE: y means it turns off kernel heap randomization for backwards compatability (libc5)
    if 'CONFIG_COMPAT_BRK=y' in kconfig:
        print("\033[31mDisabled\033[m")
    else:
        print("\033[32mEnabled\033[m")

    if 'CONFIG_CC_STACKPROTECTOR' in kconfig or 'CONFIG_STACKPROTECTOR' in kconfig:
        print("  GCC stack protector support:            ", end="")
        if (
            'CONFIG_CC_STACKPROTECTOR=y' in kconfig
            or 'CONFIG_STACKPROTECTOR=y' in kconfig
        ):
            print("\033[32mEnabled\033[m")

            if (
                'CONFIG_CC_STACKPROTECTOR_STRONG' in kconfig
                or 'CONFIG_STACKPROTECTOR_STRONG' in kconfig
            ):
                print("  GCC stack protector strong:             ", end="")
                if (
                    'CONFIG_CC_STACKPROTECTOR_STRONG=y' in kconfig
                    or 'CONFIG_STACKPROTECTOR_STRONG=y' in kconfig
                ):
                    print("\033[32mEnabled\033[m")
                else:
                    print("\033[31mDisabled\033[m")
        else:
            print("\033[31mDisabled\033[m")

    if 'CONFIG_GCC_PLUGIN_STRUCTLEAK' in kconfig:
        print("  GCC structleak plugin:                  ", end="")
        if 'CONFIG_GCC_PLUGIN_STRUCTLEAK=y' in kconfig:
            print("\033[32mEnabled\033[m")
            print("  GCC structleak by ref plugin:           ", end="")
            if 'CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL=y' in kconfig:
                print("\033[32mEnabled\033[m")
            else:
                print("\033[32mEnabled\033[m")
        else:
            print("\033[31mDisabled\033[m")

    if 'CONFIG_SLAB_FREELIST_RANDOM' in kconfig:
        print("  SLAB freelist randomization:            ", end="")
        if 'CONFIG_SLAB_FREELIST_RANDOM=y' in kconfig:
            print("\033[32mEnabled\033[m")
        else:
            print("\033[31mDisabled\033[m")

    if 'CPU_SW_DOMAIN_PAN=y' in kconfig:
        print("  Use CPU domains:                        ", end="")
        if 'CPU_SW_DOMAIN_PAN=y' in kconfig:
            print("\033[32mEnabled\033[m")
        else:
            print("\033[31mDisabled\033[m")

    if 'CONFIG_VMAP_STACK' in kconfig:
        print("  Virtually-mapped kernel stack:          ", end="")
        if 'CONFIG_VMAP_STACK=y' in kconfig:
            print("\033[32mEnabled\033[m")
        else:
            print("\033[31mDisabled\033[m")

    if 'CONFIG_STRICT_DEVMEM' in kconfig:
        print("  Restrict /dev/mem access:               ", end="")
        if 'CONFIG_STRICT_DEVMEM=y' in kconfig:
            print("\033[32mEnabled\033[m")
        else:
            print("\033[31mDisabled\033[m")

    if 'CONFIG_IO_STRICT_DEVMEM' in kconfig:
        print("  Restrict I/O access to /dev/mem:        ", end="")
        if 'CONFIG_IO_STRICT_DEVMEM=y' in kconfig:
            print("\033[32mEnabled\033[m")
        else:
            print("\033[31mDisabled\033[m")

    if 'CONFIG_REFCOUNT_FULL' in kconfig:
        print("  Full reference count validation:        ", end="")
        if 'CONFIG_REFCOUNT_FULL=y' in kconfig:
            print("\033[32mEnabled\033[m")
        else:
            print("\033[31mDisabled\033[m")

    print("  Exec Shield:                            ", end="")
    execshield = helpers.get_stdout('sysctl -n kernel.exec-shield 2> /dev/null').strip()
    if not execshield:
        print("\033[32mUnsupported\033[m")
    elif execshield == "1":
        print("\033[32mEnabled\033[m")
    else:
        print("\033[31mDisabled\033[m")

    print("  YAMA:                                   ", end="")
    yama_ptrace_scope = helpers.get_stdout(
        'sysctl -n kernel.yama.ptrace_scope 2> /dev/null'
    ).strip()
    if not yama_ptrace_scope:
        print("\033[31mDisabled\033[m\n")
    elif yama_ptrace_scope == "0":
        print("\033[31mInactive\033[m\n")
    else:
        print("\033[32mActive\033[m\n")

    if 'CONFIG_HARDENED_USERCOPY' in kconfig:
        print("  Hardened Usercopy:                      ", end="")
        if 'CONFIG_HARDENED_USERCOPY=y' in kconfig:
            print("\033[32mEnabled\033[m")
        else:
            print("\033[31mDisabled\033[m")

    if 'CONFIG_FORTIFY_SOURCE' in kconfig:
        print("  Harden str/mem functions:               ", end="")
        if 'CONFIG_FORTIFY_SOURCE=y' in kconfig:
            print("\033[32mEnabled\033[m")
        else:
            print("\033[31mDisabled\033[m")

    if 'CONFIG_DEVKMEM' in kconfig:
        print("  Restrict /dev/kmem access:              ", end="")
        if 'CONFIG_DEVKMEM=y' in kconfig:
            print("\033[31mDisabled\033[m")
        else:
            print("\033[32mEnabled\033[m")

    # x86 only
    if arch in ['32', '64']:
        print("\n* X86 only:            ")

        if 'CONFIG_PAX_SIZE_OVERFLOW=y' not in kconfig:
            if 'CONFIG_DEBUG_STRICT_USER_COPY_CHECKS' in kconfig:
                print("  Strict user copy checks:                ", end="")
                if 'CONFIG_DEBUG_STRICT_USER_COPY_CHECKS=y' in kconfig:
                    print("\033[32mEnabled\033[m")
                else:
                    print("\033[31mDisabled\033[m")

        if 'CONFIG_RANDOMIZE_BASE' in kconfig or 'CONFIG_PAX_ASLR' in kconfig:
            print("  Address space layout randomization:     ", end="")
            if 'CONFIG_RANDOMIZE_BASE=y' in kconfig or 'CONFIG_PAX_ASLR=y' in kconfig:
                print("\033[32mEnabled\033[m")
            else:
                print("\033[31mDisabled\033[m")

    # ARM only
    if arch == 'arm':
        print("\n* ARM only:            ")

        if 'CONFIG_ARM_KERNMEM_PERMS' in kconfig:
            print("  Restrict kernel memory permissions:     ", end="")
            if 'CONFIG_ARM_KERNMEM_PERMS=y' in kconfig:
                print("\033[32mEnabled\033[m")
            else:
                print("\033[31mDisabled\033[m")

        if 'CONFIG_DEBUG_ALIGN_RODATA' in kconfig:
            print("  Make rodata strictly non-excutable:     ", end="")
            if 'CONFIG_DEBUG_ALIGN_RODATA=y' in kconfig:
                print("\033[32mEnabled\033[m")
            else:
                print("\033[31mDisabled\033[m")
    # riscv64 only
    if arch == 'riscv':
        print("\n* RISCV only:            ")

    # ARM64 only
    if arch == 'aarch64':
        print("\n* ARM64 only:            ")

        if 'CONFIG_UNMAP_KERNEL_AT_EL0' in kconfig:
            print("  Unmap kernel in userspace (KAISER):     ", end="")
            if 'CONFIG_UNMAP_KERNEL_AT_EL0=y' in kconfig:
                print("\033[32mEnabled\033[m")
            else:
                print("\033[31mDisabled\033[m")

        if 'CONFIG_HARDEN_BRANCH_PREDICTOR' in kconfig:
            print("  Harden branch predictor:                ", end="")
            if 'CONFIG_HARDEN_BRANCH_PREDICTOR=y' in kconfig:
                print("\033[32mEnabled\033[m")
            else:
                print("\033[31mDisabled\033[m")

        if 'CONFIG_HARDEN_EL2_VECTORS' in kconfig:
            print("  Harden EL2 vector mapping:              ", end="")
            if 'CONFIG_HARDEN_EL2_VECTORS=y' in kconfig:
                print("\033[32mEnabled\033[m")
            else:
                print("\033[31mDisabled\033[m")

        if 'CONFIG_ARM64_SSBD' in kconfig:
            print("  Speculative store bypass disable:       ", end="")
            if 'CONFIG_ARM64_SSBD=y' in kconfig:
                print("\033[32mEnabled\033[m")
            else:
                print("\033[31mDisabled\033[m")

        if 'CONFIG_ARM64_SW_TTBR0_PAN' in kconfig:
            print("  Emulate privileged access never:        ", end="")
            if 'CONFIG_ARM64_SW_TTBR0_PAN=y' in kconfig:
                print("\033[32mEnabled\033[m")
            else:
                print("\033[31mDisabled\033[m")

        if 'CONFIG_RANDOMIZE_BASE' in kconfig:
            print("  Randomize address of kernel image:      ", end="")
            if 'CONFIG_RANDOMIZE_BASE=y' in kconfig:
                print("\033[32mEnabled\033[m")
            else:
                print("\033[31mDisabled\033[m")

        if 'CONFIG_RANDOMIZE_MODULE_REGION_FULL' in kconfig:
            print("  Randomize module region over 4GB:       ", end="")
            if 'CONFIG_RANDOMIZE_MODULE_REGION_FULL=y' in kconfig:
                print("\033[32mEnabled\033[m")
            else:
                print("\033[31mDisabled\033[m")

    print("\n* SELinux:                                ", end="")
    if 'CONFIG_SECURITY_SELINUX=y' in kconfig:
        sestatus = getsestatus()
        if sestatus == 0:
            print("\033[31mDisabled\033[m")
            print("\n  SELinux infomation available here: \n", end="")
            print("    http://selinuxproject.org/\n", end="")
        elif sestatus == 1:
            print("\033[33mPermissive\033[m")
        elif sestatus == 2:
            print("\033[32mEnforcing\033[m")

        # bugfix
        if sestatus in [1, 2]:
            print("  Checkreqprot:                         ", end="")
            with open('/sys/fs/selinux/checkreqprot', 'r') as f:
                if f.read().strip() == '0':
                    print("\033[32m  Enabled\033[m")
                else:
                    print("\033[31m  Disabled\033[m")

            print("  Deny Unknown:                         ", end="")
            with open('/sys/fs/selinux/deny_unknown', 'r') as f:
                if f.read().strip() == '1':
                    print("\033[32m  Enabled\033[m")
                else:
                    print("\033[31m  Disabled\033[m")
    else:
        print("\033[31mNo SELinux\033[m")
        print("\n  SELinux infomation available here: ")
        print("    http://selinuxproject.org/")

    print()
