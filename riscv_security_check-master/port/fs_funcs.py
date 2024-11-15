def fs_libc_check(fs_chk_func_libc: list[str]):
    print("* FORTIFY_SOURCE support available (libc)    : ", end="")

    if fs_chk_func_libc:
        print("\033[32mYes\033[m")
    else:
        print("\033[31mNo\033[m")
        assert False


def fs_binary_check(fs_functions: list[str]):
    print("* Binary compiled with FORTIFY_SOURCE support: ", end="")

    for elem in fs_functions:
        if '_chk' in elem:
            print("\033[32mYes\033[m")
            return
    print("\033[31mNo\033[m")


def fs_comparison(fs_functions: list[str], fs_chk_func_libc: list[str]):
    print()
    print(" ------ EXECUTABLE-FILE ------- . -------- LIBC --------")
    print(" Fortifiable library functions  | Checked function names")
    print(" -------------------------------------------------------")

    fs_chk_func_libc = set(fs_chk_func_libc)
    fs_cnt_unchecked, fs_cnt_checked = 0, 0
    for fn in fs_functions:
        if fn in fs_chk_func_libc:
            print(" \033[31m%-30s\033[m | __%s_chk" % (fn, fn))
            fs_cnt_unchecked += 1
        elif fn.endswith('_chk') and fn[:-4] in fs_chk_func_libc:
            print(" \033[32m%-30s\033[m | __%s_chk" % (fn, fn))
            fs_cnt_checked += 1

    return fs_cnt_checked, fs_cnt_unchecked


def fs_summary(
    fs_functions: list[str],
    fs_chk_func_libc: list[str],
    fs_cnt_checked: int,
    fs_cnt_unchecked: int,
):
    fs_cnt_total = fs_cnt_checked + fs_cnt_unchecked
    print()
    print("SUMMARY:\n")
    print(
        f"* Number of checked functions in libc                : {len(fs_chk_func_libc)}"
    )
    print(f"* Total number of library functions in the executable: {len(fs_functions)}")
    print(f"* Number of Fortifiable functions in the executable  : {fs_cnt_total}")
    print(
        f"* Number of checked functions in the executable      : \033[32m{fs_cnt_checked}\033[m"
    )
    print(
        f"* Number of unchecked functions in the executable    : \033[31m{fs_cnt_unchecked}\033[m"
    )
    print()
