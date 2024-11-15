import os
import re
import argparse
import subprocess


'''
FunctionName:
Argument:
Result:
Comment:
'''
def IsElfFile(inputFilePath):
    try:
        result = subprocess.run(['file', inputFilePath], capture_output=True, text=True, check=True)
        return 'ELF' in result.stdout
    except subprocess.CalledProcessError:
        return False

'''
FunctionName:
    CollectElfFiles

Argument:

Result:

Comment:

'''
def CollectElfFiles(inputDirectory):
    listElfFile = []
    listDir     = []

    print("EmunerateFiles")
    for root, dirs, files in os.walk(inputDirectory):
        for file in files:
            file_path = os.path.join(root, file)
            if IsElfFile(file_path):
                print(file_path)


    # 遍历目录下所有文件和子目录
    for root, dirs, files in os.walk(inputDirectory):
        # 收集当前目录下的文件
        for file in files:
            file_path = os.path.join(root, file)
            if IsElfFile(file_path):
                listElfFile.append(file_path)

        # 收集当前目录下的子目录
        for dir in dirs:
            dir_path = os.path.join(root, dir)
            listDir.append(dir_path)
            
        for dir in listDir:
            listElfFile = listElfFile + CollectElfFiles(dir)

    return listElfFile

'''
FunctionName:
Argument:
Result:
Comment:
'''
# check if directory exists
def CheckDirExists(inputDirectory):
  if os.path.exists(inputDirectory):
    return False
  else:
    return True


'''
FunctionName:
Argument:
Result:
Comment:
'''
# check user privileges
def CheckRootPrivs():
    privs = None
    result = os.popen('id -u')
    context = result.read()
    for line in context.splitlines():
        privs = line
        print(line)
    result.close()
    if privs == "0":
        return False
    else:
        return True

'''
FunctionName:
Argument:
Result:
Comment:
'''
# check for required files and deps first
# check if command exists
def CheckCommandExists(inputCommandString):
    result = os.popen("type " + inputCommandString)
    context = result.read()
    for line in context.splitlines():
        text = line
        print(line)
    result.close()
    if text.find("not found") >= 0 :
        print("not exist")
        return False
    elif text.find("is") >= 0 :
        print("exist")
        return True



def search_libc():
    global FS_libc
    
    if not FS_libc:
        # if a specific search path is given, use it
        if 'LIBC_FILE' in globals() and LIBC_FILE:
            if os.path.isfile(LIBC_FILE):
                FS_libc = LIBC_FILE
            elif os.path.isdir(LIBC_FILE):
                LIBC_SEARCH_PATH = LIBC_FILE
        
        # otherwise use ldconfig to get the libc location
        elif subprocess.run(['ldconfig', '-p'], capture_output=True).stdout:
            ldconfig_output = subprocess.run(['ldconfig', '-p'], capture_output=True).stdout.decode('utf-8')
            libc_location = next((line.split()[3] for line in ldconfig_output.splitlines() if 'libc.so' in line), None)
            if libc_location and os.path.isfile(libc_location):
                FS_libc = libc_location
        
        # if a search path was given or ldconfig failed we need to search for libc
        if not FS_libc:
            # if a search path was specified, look for libc in LIBC_SEARCH_PATH
            if 'LIBC_SEARCH_PATH' in globals() and LIBC_SEARCH_PATH:
                for root, dirs, files in os.walk(LIBC_SEARCH_PATH):
                    for filename in files:
                        if filename.startswith("libc.so."):
                            FS_libc = os.path.join(root, filename)
                            break
                    if FS_libc:
                        break
            # if ldconfig failed, then as a last resort search for libc in "/lib/", "/lib64/" and "/"
            else:
                search_paths = ['/lib/', '/lib64/', '/']
                for path in search_paths:
                    FS_libc = next((os.path.join(path, filename) for filename in os.listdir(path) if filename.startswith("libc.so.")), None)
                    if FS_libc:
                        break
        
        # FS_libc is used across multiple functions
        if FS_libc and os.path.exists(FS_libc):
            os.environ['FS_libc'] = FS_libc
        else:
            print("\033[31mError: libc not found.\033[m\n\n")
            exit(1)

'''
FunctionName:
Argument:
Result:
Comment:
'''
def GetSysArch():
    arch = None
    result = os.popen('uname -m')
    context = result.read()
    for line in context.splitlines():
        sysarch = line
        print(line)
    result.close()
    if sysarch == "x86_64":
        arch="64"
    elif sysarch == "i?86":
        arch="32"
    elif sysarch == "arm":
        arch="arm"
    elif sysarch == "aarch64":
        arch="aarch64"
    print(arch)

'''
FunctionName:
Argument:
Result:
Comment:
'''
def echo_message(message, desc1, desc2, desc3):
    print(message)
    if desc1:
        print(desc1)
    if desc2:
        print(desc2)
    if desc3:
        print(desc3)
    print()

'''
FunctionName:
Argument:
Result:
Comment:
'''
def format():
    global output_format
    
    valid_formats = ["cli", "csv", "xml", "json"]
    if output_format:
        if output_format not in valid_formats:
            print("\033[31mError: Please provide a valid format {cli, csv, xml, json}.\033[m\n\n")
            exit(1)
    
    if output_format == "xml":
        print('<?xml version="1.0" encoding="UTF-8"?>')
    
    format = output_format

'''
FunctionName:
Argument:
Result:
Comment:
'''
def kernelcheck(configfile=None):
    try:
        if configfile:
            subprocess.run(['kernelcheck', configfile], check=True)
        else:
            subprocess.run(['kernelcheck'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        exit(1)

def chk_kernel():
    global CHK_KERNEL

    if CHK_KERNEL == "kernel":
        CHK_KERNEL = ""

    if os.path.exists(CHK_KERNEL) and not os.path.isdir(CHK_KERNEL):
        if os.path.isfile(os.path.join(os.getcwd(), CHK_KERNEL)) and os.path.getsize(os.path.join(os.getcwd(), CHK_KERNEL)) > 0:
            configfile = os.path.join(os.getcwd(), CHK_KERNEL)
        elif os.path.isfile(CHK_KERNEL) and os.path.getsize(CHK_KERNEL) > 0:
            configfile = CHK_KERNEL
        else:
            print("Error: config file specified does not exist")
            exit(1)
        
        echo_message(f"* Kernel protection information for : {configfile} \n\n", "", "", "")
        os.chdir('/proc')
        kernelcheck(configfile)
    else:
        os.chdir('/proc')
        echo_message("* Kernel protection information:\n\n", "", "", "")
        kernelcheck()

def aslrcheck():
    try:
        # PaX ASLR support
        if not subprocess.run(['grep', 'Name:', '/proc/1/status'], stderr=subprocess.DEVNULL).returncode == 0:
            echo_message('\033[33m insufficient privileges for PaX ASLR checks\033[m\n', '', '', '')
            echo_message('  Fallback to standard Linux ASLR check', '', '', '')

        if 'PaX:' in subprocess.run(['grep', 'PaX:', '/proc/1/status'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode('utf-8'):
            if 'R' in subprocess.run(['grep', 'PaX:', '/proc/1/status'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode('utf-8'):
                echo_message('\033[32mPaX ASLR enabled\033[m\n\n', '', '', '')
            else:
                echo_message('\033[31mPaX ASLR disabled\033[m\n\n', '', '', '')
        else:
            # standard Linux 'kernel.randomize_va_space' ASLR support
            sysctl_output = subprocess.run(['sysctl', '-a'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode('utf-8')
            if 'kernel.randomize_va_space = 1' in sysctl_output:
                echo_message(" (kernel.randomize_va_space): ", '', '', '')
                echo_message('\033[33mPartial (Setting: 1)\033[m\n\n', '', '', '')
                echo_message("  Description - Make the addresses of mmap base, stack and VDSO page randomized.\n", '', '', '')
                echo_message("  This, among other things, implies that shared libraries will be loaded to \n", '', '', '')
                echo_message("  random addresses. Also for PIE-linked binaries, the location of code start\n", '', '', '')
                echo_message("  is randomized. Heap addresses are *not* randomized.\n\n", '', '', '')
            elif 'kernel.randomize_va_space = 2' in sysctl_output:
                echo_message(" (kernel.randomize_va_space): ", '', '', '')
                echo_message('\033[32mFull (Setting: 2)\033[m\n\n', '', '', '')
                echo_message("  Description - Make the addresses of mmap base, heap, stack and VDSO page randomized.\n", '', '', '')
                echo_message("  This, among other things, implies that shared libraries will be loaded to random \n", '', '', '')
                echo_message("  addresses. Also for PIE-linked binaries, the location of code start is randomized.\n\n", '', '', '')
            elif 'kernel.randomize_va_space = 0' in sysctl_output:
                echo_message(" (kernel.randomize_va_space): ", '', '', '')
                echo_message('\033[31mNone (Setting: 0)\033[m\n', '', '', '')
            else:
                echo_message('\033[31mNot supported\033[m\n', '', '', '')
            echo_message("  See the kernel file 'Documentation/admin-guide/sysctl/kernel.rst' for more details.\n\n", '', '', '')

    except Exception as e:
        print(f"Error: {e}")
        exit(1)


'''
FunctionName:
    CheckNX

Argument:
    None

Result:
    None

Comment:
'''
def CheckNX():
    # check cpu nx flag
    nx = None
    result = os.popen('grep -Fw \'nx\' /proc/cpuinfo')
    # 返回的结果是一个<class 'os._wrap_close'>对象，需要读取后才能处理
    context = result.read()
    for line in context.splitlines():
        nx = line
        print(line)
    result.close()
    if nx != None:
        print('\033[32mYes\033[m\n\n' '' '' '')
    else:
        print('\033[31mNo\033[m\n\n' '' '' '')

'''
FunctionName:
    CheckFortifyFile

Argument:

Result:
Comment:
'''
def CheckFortifyFile():
    # Check if first character of pathname is '~' and replace it with '${HOME}'
    chk_fortify_file = os.getenv('CHK_FORTIFY_FILE')
    if chk_fortify_file and chk_fortify_file.startswith('~'):
        chk_fortify_file = os.path.expanduser(chk_fortify_file)
    
    if not chk_fortify_file:
        print("\033[31mError: Please provide a valid file.\033[m\n\n")
        exit(1)
    
    # Does the file exist?
    if not os.path.isfile(chk_fortify_file):
        print("\033[31mError: The file '{}' does not exist.\033[m\n\n".format(chk_fortify_file))
        exit(1)
    
    # Read permissions?
    if not os.access(chk_fortify_file, os.R_OK):
        print("\033[31mError: No read permissions for '{}' (run as root).\033[m\n\n".format(chk_fortify_file))
        exit(1)
    
    # Check if file is an ELF executable
    out = os.popen('file -b "{}"'.format(os.path.realpath(chk_fortify_file))).read().strip()
    if 'ELF' not in out:
        print("\033[31mError: Not an ELF file: {}\033[m".format(out))
        exit(1)


def filecheck(file_path):
    # check for RELRO support
    readelf_cmd = ['readelf', '-l', file_path]
    readelf_output = subprocess.run(readelf_cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)
    
    if "no program headers" in readelf_output.stdout:
        echo_message('\033[32mN/A          \033[m   ')
        echo_message('N/A,')
        echo_message('<file relro="n/a"')
        echo_message(f' "{{\"{file_path}\": {{"relro":"n/a",')
    elif re.search(r'GNU_RELRO', readelf_output.stdout):
        bind_now_cmd = ['readelf', '-d', file_path]
        bind_now_output = subprocess.run(bind_now_cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)
        
        if re.search(r'BIND_NOW', bind_now_output.stdout) or not re.search(r'\.got\.plt', readelf_output.stdout):
            echo_message('\033[32mFull RELRO   \033[m   ')
            echo_message('Full RELRO,')
            echo_message('<file relro="full"')
            echo_message(f' "{{\"{file_path}\": {{"relro":"full",')
        else:
            echo_message('\033[33mPartial RELRO\033[m   ')
            echo_message('Partial RELRO,')
            echo_message('<file relro="partial"')
            echo_message(f' "{{\"{file_path}\": {{"relro":"partial",')
    else:
        echo_message('\033[31mNo RELRO     \033[m   ')
        echo_message('No RELRO,')
        echo_message('<file relro="no"')
        echo_message(f' "{{\"{file_path}\": {{"relro":"no",')

    # fallback on dynamic section to retrieve symbols when symbol table is unavailable
    use_dynamic = ''
    dynamic_symbol_cmd = ['readelf', '-s', file_path]
    dynamic_symbol_output = subprocess.run(dynamic_symbol_cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)
    
    if "Dynamic symbol information is not available" in dynamic_symbol_output.stdout:
        use_dynamic = '--use-dynamic'

    # check for stack canary support
    canary_cmd = ['readelf', '-s', use_dynamic, file_path]
    canary_output = subprocess.run(canary_cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)
    
    if re.search(r' UND ', canary_output.stdout) and any(sym in canary_output.stdout for sym in ['__stack_chk_fail', '__stack_chk_guard', '__intel_security_cookie']):
        echo_message('\033[32mCanary found   \033[m   ')
        echo_message('Canary found,')
        echo_message(' canary="yes"')
        echo_message('"canary":"yes",')
    else:
        echo_message('\033[31mNo canary found\033[m   ')
        echo_message('No Canary found,')
        echo_message(' canary="no"')
        echo_message('"canary":"no",')

    # check for NX support
    nx_cmd = ['readelf', '-l', file_path]
    nx_output = subprocess.run(nx_cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)
    
    if "no program headers" in nx_output.stdout:
        echo_message('\033[32mN/A        \033[m   ')
        echo_message('N/A,')
        echo_message(' nx="n/a"')
        echo_message('"nx":"n/a",')
    elif re.search(r'GNU_STACK', nx_output.stdout):
        stack_cmd = ['readelf', '-l', file_path]
        stack_output = subprocess.run(stack_cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)
        
        if re.search(r'(0x[0-9a-f]+)RW ', stack_output.stdout):
            echo_message('\033[31mNX disabled\033[m   ')
            echo_message('NX disabled,')
            echo_message(' nx="no"')
            echo_message('"nx":"no",')
        else:
            echo_message('\033[32mNX enabled \033[m   ')
            echo_message('NX enabled,')
            echo_message(' nx="yes"')
            echo_message('"nx":"yes",')
    else:
        echo_message('\033[31mNX disabled\033[m   ')
        echo_message('NX disabled,')
        echo_message(' nx="no"')
        echo_message('"nx":"no",')

    # check for PIE support
    pie_cmd = ['readelf', '-h', file_path]
    pie_output = subprocess.run(pie_cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)
    
    if re.search(r'Type:[[:space:]]*EXEC', pie_output.stdout):
        echo_message('\033[31mNo PIE       \033[m   ')
        echo_message('No PIE,')
        echo_message(' pie="no"')
        echo_message('"pie":"no",')
    elif re.search(r'Type:[[:space:]]*DYN', pie_output.stdout):
        debug_cmd = ['readelf', '-d', file_path]
        debug_output = subprocess.run(debug_cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)
        
        if re.search(r'DEBUG', debug_output.stdout):
            echo_message('\033[32mPIE enabled  \033[m   ')
            echo_message('PIE enabled,')
            echo_message(' pie="yes"')
            echo_message('"pie":"yes",')
        else:
            echo_message('\033[33mDSO          \033[m   ')
            echo_message('DSO,')
            echo_message(' pie="dso"')
            echo_message('"pie":"dso",')
    elif re.search(r'Type:[[:space:]]*REL', pie_output.stdout):
        echo_message('\033[33mREL          \033[m   ')
        echo_message('REL,')
        echo_message(' pie="rel"')
        echo_message('"pie":"rel",')
    else:
        echo_message('\033[33mNot an ELF file\033[m   ')
        echo_message('Not an ELF file,')
        echo_message(' pie="not_elf"')
        echo_message('"pie":"not_elf",')

    # check for extended checks
    extended_checks = True  # Assuming this is a global variable
    if extended_checks:
        # check for selfrando support
        selfrando_cmd = ['readelf', '-S', file_path]
        selfrando_output = subprocess.run(selfrando_cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)
        
        if re.search(r'txtrp', selfrando_output.stdout) and selfrando_output.stdout.count('txtrp') == 1:
            echo_message('\033[32mSelfrando enabled  \033[m   ')
        else:
            echo_message('\033[31mNo Selfrando       \033[m   ')

        # check if compiled with Clang CFI
        cfi_func_cmd = ['readelf', '-s', use_dynamic, file_path]
        cfi_func_output = subprocess.run(cfi_func_cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)
        
        cfifunc = re.findall(r'\.cfi', cfi_func_output.stdout)
        func = cfifunc[0].replace('.cfi', '')
        if func and func in cfi_func_output.stdout:
            echo_message('\033[32mClang CFI found   \033[m   ')
            echo_message('with CFI,')
            echo_message(' clangcfi="yes"')
            echo_message('"clangcfi":"yes",')
        else:
            echo_message('\033[31mNo Clang CFI found\033[m   ')
            echo_message('without CFI,')
            echo_message(' clangcfi="no"')
            echo_message('"clangcfi":"no",')

        # check if compiled with Clang SafeStack
        safestack_cmd = ['readelf', '-s', use_dynamic, file_path]
        safestack_output = subprocess.run(safestack_cmd, capture_output=True, text=True, stderr=subprocess.DEVNULL)
        
        if re.search(r'__safestack_init', safestack_output.stdout):
            echo_message('\033[32mSafeStack found   \033[m   ')
            echo_message('with SafeStack,')
            echo_message(' safestack="yes"')
            echo_message('"safestack":"yes",')
        else:
            echo_message('\033[31mNo SafeStack found\033[m   ')
            echo_message('without SafeStack,')
            echo_message(' safestack="no"')
            echo_message('"safestack":"no",')

    # check for rpath
    dynamic_section_output = readelf(readelf_command + " -d " + filename)
    if "no dynamic section" in dynamic_section_output:
        echo_message('\033[32mN/A      \033[m  ', 'N/A,', ' rpath="n/a"' '"rpath":"n/a",')
    else:
        rpath_array_output = readelf(readelf_command + " -d " + filename + " | awk -F'[][]' '/RPATH/ {print $2}'")
        rpath_array = rpath_array_output.strip().split(':') if rpath_array_output else []
        if len(rpath_array) > 0:
            if any(re.search(r'\brw\b', xargs_stat_output) for xargs_stat_output in subprocess.check_output(['xargs', 'stat', '-c', '%A'] + rpath_array, stderr=subprocess.DEVNULL, text=True).split('\n')):
                echo_message('\033[31mRW-RPATH \033[m  ', 'RPATH,', ' rpath="yes"' '"rpath":"yes",')
            else:
                echo_message('\033[31mRPATH   \033[m  ', 'RPATH,', ' rpath="yes"' '"rpath":"yes",')
        else:
            echo_message('\033[32mNo RPATH \033[m  ', 'No RPATH,', ' rpath="no"' '"rpath":"no",')

    # check for runpath
    dynamic_section_output = readelf(readelf_command + " -d " + filename)
    if "no dynamic section" in dynamic_section_output:
        echo_message('\033[32mN/A        \033[m  ', 'N/A,', ' runpath="n/a"' '"runpath":"n/a",')
    else:
        runpath_array_output = readelf(readelf_command + " -d " + filename + " | awk -F'[][]' '/RUNPATH/ {print $2}'")
        runpath_array = runpath_array_output.strip().split(':') if runpath_array_output else []
        if len(runpath_array) > 0:
            if any(re.search(r'\brw\b', xargs_stat_output) for xargs_stat_output in subprocess.check_output(['xargs', 'stat', '-c', '%A'] + runpath_array, stderr=subprocess.DEVNULL, text=True).split('\n')):
                echo_message('\033[31mRW-RUNPATH \033[m  ', 'RUNPATH,', ' runpath="yes"' '"runpath":"yes",')
            else:
                echo_message('\033[31mRUNPATH   \033[m  ', 'RUNPATH,', ' runpath="yes"' '"runpath":"yes",')
        else:
            echo_message('\033[32mNo RUNPATH \033[m  ', 'No RUNPATH,', ' runpath="no"' '"runpath":"no",')

    # check for stripped symbols
    symtab_output = readelf(readelf_command + " --symbols " + filename)
    if ".symtab" in symtab_output:
        sym_cnt = symtab_output.splitlines()[0].split()[4].split(':')[0]
        echo_message("\033[31m{} Symbols\t\033[m".format(sym_cnt), 'Symbols,', ' symbols="yes"' '"symbols":"yes",')
    else:
        echo_message('\033[32mNo Symbols\t\033[m', 'No Symbols,', ' symbols="no"' '"symbols":"no",')

    # additional checks
    search_libc_output = search_libc(filename, readelf_command)
    libc_found = "true" if "libc.so" in search_libc_output else "false"
    
    FS_filechk_func_libc_output = readelf(readelf_command + " -s " + search_libc_output + " | sed -ne 's/.*__\(.*_chk\)@@.*/\\1/p'")
    FS_filechk_func_libc = re.sub(r'_chk', '', FS_filechk_func_libc_output.strip()) if FS_filechk_func_libc_output else ''
    
    FS_func_output = readelf(readelf_command + " -s " + filename + " | awk '{ print $8 }' | sed -e 's/_*//' -e 's/@.*//' -e '/^$/d'")
    FS_func = FS_func_output.strip().split('\n') if FS_func_output else []
    
    FS_cnt_checked = len(set(FS_filechk_func_libc.splitlines()) & set(FS_func.splitlines()))
    FS_cnt_unchecked = len(set(FS_func.splitlines()) - set(FS_filechk_func_libc.splitlines()))
    FS_cnt_total = FS_cnt_unchecked + FS_cnt_checked
    
    if libc_found == "false" or FS_cnt_total == 0:
        echo_message("\033[32mN/A\033[m", "N/A,", ' fortify_source="n/a" ' '"fortify_source":"n/a",')
    elif FS_cnt_checked == 0:
        echo_message("\033[31mNo\033[m", "No,", ' fortify_source="no" ' '"fortify_source":"no",')
    else:
        echo_message('\033[32mYes\033[m', 'Yes,', ' fortify_source="yes" ' '"fortify_source":"yes",')
    
    echo_message("\t{}\t".format(FS_cnt_checked), "{},".format(FS_cnt_checked), ' fortified="{}" '.format(FS_cnt_checked), '"fortified":"{}"'.format(FS_cnt_checked))
    echo_message("\t{}\t\t".format(FS_cnt_total), "{}".format(FS_cnt_total), ' fortify-able="{}"'.format(FS_cnt_total), '"fortify-able":"{}"'.format(FS_cnt_total))

def search_libc(filename, readelf_command='readelf'):
    libc_found = readelf(readelf_command + " -d " + filename + " | grep NEEDED | grep -q libc\.so")
    return libc_found



def libcheck(pid):
    try:
        # Read mapped libraries from /proc/<pid>/maps, filter by ELF files
        proc_maps = subprocess.run(['awk', '{ print $6 }', f"/proc/{pid}/maps"], capture_output=True, text=True, check=True)
        libs = proc_maps.stdout.strip().split('\n')
        libs = [lib for lib in libs if '/' in lib]
        libs = list(set(libs))  # Remove duplicates and sort

        # Get file information (ELF files)
        file_info = subprocess.run(['file'] + libs, capture_output=True, text=True, check=True)
        elf_libs = [line.split(':')[0] for line in file_info.stdout.splitlines() if 'ELF' in line]

        echo_message(f"\n* Loaded libraries (file information, # of mapped files: {len(elf_libs)}):\n\n", "", "", "\"libs\": {")
        
        # Iterate over ELF libraries
        for index, lib in enumerate(elf_libs):
            echo_message(f"  {lib}:\n", f"{lib},", "    ", "")
            echo_message("    ", "    ", "    ", "")
            filecheck(lib)
            if index == len(elf_libs) - 1:
                echo_message("\n\n", "\n", f" filename='{lib}' />\n", "")
            else:
                echo_message("\n\n", "\n", f" filename='{lib}' />\n", "},")

    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        exit(1)

def PrintHelp():
    print("help")



def kernelcheck():
    print("  Description - List the status of kernel protection mechanisms. Rather than\n" '' '' '')
    print("  inspect kernel mechanisms that may aid in the prevention of exploitation of\n" '' '' '')
    print("  userspace processes, this option lists the status of kernel configuration\n" '' '' '')
    print("  options that harden the kernel itself against attack.\n\n" '' '' '')
    print("  Kernel config:\n" '' '' '{ "kernel": ')

def CommandExist():
    print("Command Exist")


if __name__== "__main__" :

    '''
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('integers', metavar='N', type=int, nargs='+',
                    help='an integer for the accumulator')
    parser.add_argument('--sum', dest='accumulate', action='store_const',
                    const=sum, default=max,
                    help='sum the integers (default: find the max)')

    args = parser.parse_args()
    print(args.accumulate(args.integers))
    kernelcheck()
    '''


    print("  Vanilla Kernel ASLR:                    " "" "" "")
    result = os.popen('sysctl -n kernel.randomize_va_space')
    # 返回的结果是一个<class 'os._wrap_close'>对象，需要读取后才能处理
    context = result.read()
    for line in context.splitlines():
        randomize_va = line
        print(line)
    result.close()
    if randomize_va == "2":
        print("Full" + "Full," + " randomize_va_space='full'" ', "randomize_va_space":"full"')
    elif randomize_va == "1":
        print("\033[33mPartial\033[m\n" + "Partial," + " randomize_va_space='partial'" ', "randomize_va_space":"partial"')
    else:
        print("\033[31mNone\033[m\n" "None," " randomize_va_space='none'" ', "randomize_va_space":"none"')
    print("\n")

    
    print("  NX protection:                          " "" "" "")
    strCommand  = None
    if CheckCommandExists("journalctl"):
        strCommand  = "journalctl -kb -o cat | grep -Fw NX | head -n 1"
    elif  CheckCommandExists("dmesg"):
        strCommand  = "dmesg -t 2> /dev/null | grep -Fw NX"
    result = os.popen(strCommand)
    # 返回的结果是一个<class 'os._wrap_close'>对象，需要读取后才能处理
    context = result.read()
    for line in context.splitlines():
        nx_protection = line
        print(line)
    result.close()
    if nx_protection != None:
        if nx_protection == "NX (Execute Disable) protection: active":
            print("\033[32mEnabled\033[m\n" "Enabled," " nx_protection='yes'" ', "nx_protection":"yes"')
        else:
            print("\033[31mDisabled\033[m\n" "Disabled," " nx_protection='no'" ', "nx_protection":"no"')
    else:
        print("\033[33mSkipped\033[m\n" "Skipped," " nx_protection='skipped'" ', "nx_protection":"skipped"')
    print("\n")


    print( "  Protected symlinks:                     " "" "" "")
    result = os.popen('sysctl -n fs.protected_symlinks')
    context = result.read()
    for line in context.splitlines():
        symlink = line
        print(line)
    result.close()
    if symlink == "1":
        print( "\033[32mEnabled\033[m\n" "Enabled," " protect_symlinks='yes'" ', "protect_symlinks":"yes"')
    else:
        print( "\033[31mDisabled\033[m\n" "Disabled," " protect_symlinks='no'" ', "protect_symlinks":"no"')
    print("\n")

    print("  Protected hardlinks:                    " "" "" "")
    result = os.popen('sysctl -n fs.protected_hardlinks')
    context = result.read()
    for line in context.splitlines():
        hardlink = line
        print(line)
    result.close()
    if hardlink == "1":
        print( "\033[32mEnabled\033[m\n" "Enabled," " protect_hardlinks='yes'" ', "protect_hardlinks":"yes"')
    else:
        print( "\033[31mDisabled\033[m\n" "Disabled," " protect_hardlinks='no'" ', "protect_hardlinks":"no"')
    print("\n")

    print("  Protected fifos:                        " "" "" "")
    result = os.popen('sysctl -n fs.protected_fifos')
    context = result.read()
    for line in context.splitlines():
        fifos = line
        print(line)
    result.close()
    if fifos == None :
        print( "\033[33mUnsupported\033[m\n" "Unsupported," " protect_fifos='unsupported'" ', "protect_fifos":"unsupported"')
    elif fifos == "1":
        print( "\033[33mPartial\033[m\n" "Partial," " protect_fifos='partial'" ', "protect_fifos":"partial"')
    elif fifos == "2":
        print( "\033[32mEnabled\033[m\n" "Enabled," " protect_fifos='yes'" ', "protect_fifos":"yes"')
    else:
        print( "\033[31mDisabled\033[m\n" "Disabled," " protect_fifos='no'" ', "protect_fifos":"no"')
    print("\n")

    print( "  Protected regular:                      " "" "" "")
    result = os.popen('sysctl -n fs.protected_regular')
    context = result.read()
    for line in context.splitlines():
        regular = line
        print(line)
    result.close()
    if regular:
        print( "\033[33mUnsupported\033[m\n" "Unsupported," " protect_regular='unsupported'" ', "protect_regular":"unsupported"')
    elif regular == "1":
        print( "\033[33mPartial\033[m\n" "Partial," " protect_regular='partial'" ', "protect_regular":"partial"')
    elif regular == "2":
        print( "\033[32mEnabled\033[m\n" "Enabled," " protect_regular='yes'" ', "protect_regular":"yes"')
    else:
        print( "\033[31mDisabled\033[m\n" "Disabled," " protect_regular='no'" ', "protect_regular":"no"')
    print("\n")

    print("  Ipv4 reverse path filtering:            " "" "" "")
    result = os.popen('sysctl -n net.ipv4.conf.all.rp_filter')
    context = result.read()
    for line in context.splitlines():
        ipv4_rpath = line
        print(line)
    result.close()
    if ipv4_rpath == "1":
        print( "\033[32mEnabled\033[m\n" "Enabled," " ipv4_rpath='yes'" ', "ipv4_rpath":"yes"')
    else:
        print( "\033[31mDisabled\033[m\n" "Disabled," " ipv4_rpath='no'" ', "ipv4_rpath":"no"')
    print("\n")

    CheckNX()
    GetSysArch()
    aslrcheck()