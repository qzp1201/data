import filecheck
import helpers


def libcheck(pid: int):
    libs = helpers.get_stdout(
        f"awk '{{ print $6 }}' /proc/{pid}/maps | grep '/' | sort -u | xargs file | grep ELF | awk '{{ print $1 }}' | sed 's/:/ /'"
    ).splitlines()
    print(f"\n* Loaded libraries (file information, # of mapped files: {len(libs)}):\n")

    # Iterate over ELF libraries
    for lib in libs:
        lib = lib.strip()
        print(f"  {lib}:")
        print("    ", end="")
        filecheck.filecheck(lib)
        print("\n")
