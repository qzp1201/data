import helpers


def nxcheck():
    # check cpu nx flag
    nx = helpers.get_exitcode('grep -qFw \'nx\' /proc/cpuinfo')
    if not nx:
        print('\033[32mYes\033[m\n')
    else:
        print('\033[31mNo\033[m\n')
