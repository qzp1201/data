import os
import glob
import subprocess
import shlex
import argparse
import stat
import os
import shlex
import filecheck
import helpers

global g_ExecutableFileList

def chk_file(file: str):
    if not file:
        print("\033[31mError: Please provide a valid file.\033[m\n")
        #assert False
        return

    if not os.path.isfile(file):
        print("\033[31mError: The file '%s' does not exist.\033[m\n")
        #assert False
        return

    if not os.access(file, os.R_OK):
        print("\033[31mError: No read permissions for '%s' (run as root).\033[m\n")
        #assert False
        return

    file_output = helpers.get_stdout('file ' + shlex.quote(os.path.realpath(file)))
    if 'ELF' not in file_output:
        print("\033[31mError: Not an ELF file: " + file_output.strip() + "\033[m")
        #assert False
        return
        
    # TODO: extended checks
    print(
        "RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH\tSymbols\t\tFORTIFY\tFortified\tFortifiable\tFILE"
    )
    filecheck.filecheck(file)
    if os.stat(file).st_mode & 0o6000:
        print(f"\033[37;41m{file}\033[m")
    else:
        print(file)

'''

'''
def is_executable(file_path):
    file_output = helpers.get_stdout('file ' + shlex.quote(os.path.realpath(file_path)))
    if 'ELF' not in file_output:
        print("\033[31mError: Not an ELF file: " + file_output.strip() + "\033[m")
        return False
    return True

'''

'''
def list_executable_files(directory):
    global g_ExecutableFileList
    # 遍历目录及其子目录
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if is_executable(file_path):
                g_ExecutableFileList.append(file_path)
                print(f"可执行文件: {file_path}")
            else:
                print(f"非可执行文件: {file_path}")





'''

'''
def EnumeratePackageContent():
    print("EnumeratePackageContent")

'''

'''
def ExtractRPMPackages(strInputRPMDirectory, strOutputDirectory):
    print("ExtractRPMPackages")
    #strDirectory = os.path.join
    rpm_files = glob.glob( strInputRPMDirectory + '/*.rpm')

    for rpm_file in rpm_files:
        assert rpm_file.startswith(strInputRPMDirectory) and rpm_file.endswith('.rpm')
        dest_dir = strOutputDirectory + '/' + os.path.basename(rpm_file[5:-4])
        print(f"Extracting {rpm_file} to {dest_dir}")
        os.makedirs(dest_dir, exist_ok=True)
        cmd = (
            f"rpm2cpio {shlex.quote(rpm_file)} | cpio -idm -D {shlex.quote(dest_dir)}"
        )
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to extract {rpm_file}: {e}")


if __name__== "__main__" :
    global g_ExecutableFileList
    g_ExecutableFileList    = []
    strRpmDirectory         = ""
    strExtractedDirectory   = ""

    parser = argparse.ArgumentParser(description='d')
    parser.add_argument('--output', '-o', type=str, help='参数2，非必须参数,包含默认值', required=True)
    parser.add_argument('--input', '-i', type=str, help='参数3，必须参数', required=True)
    args = parser.parse_args()
    strRpmDirectory         = args.input
    strExtractedDirectory   = args.output

    print(args.input)
    print(args.output)
    ExtractRPMPackages(strRpmDirectory,strExtractedDirectory)
    #
    
    
    # 使用示例：指定你要遍历的目录
    
    list_executable_files(strExtractedDirectory)
    for current_file in g_ExecutableFileList:
        chk_file(current_file)

