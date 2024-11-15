import os
import shlex
import filecheck
import helpers


def chk_file(file: str):
    if not file:
        print("\033[31mError: Please provide a valid file.\033[m\n")
        assert False

    if not os.path.isfile(file):
        print("\033[31mError: The file '%s' does not exist.\033[m\n")
        assert False

    if not os.access(file, os.R_OK):
        print("\033[31mError: No read permissions for '%s' (run as root).\033[m\n")
        assert False

    file_output = helpers.get_stdout('file ' + shlex.quote(os.path.realpath(file)))
    if 'ELF' not in file_output:
        print("\033[31mError: Not an ELF file: " + file_output.strip() + "\033[m")
        assert False

    # TODO: extended checks
    print(
        "RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH\tSymbols\t\tFORTIFY\tFortified\tFortifiable\tFILE"
    )
    filecheck.filecheck(file)
    if os.stat(file).st_mode & 0o6000:
        print(f"\033[37;41m{file}\033[m")
    else:
        print(file)
