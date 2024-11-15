import os
import helpers


def coredumpcheck():
    coreValue = 0
    coreValueDefault = 0
    if os.path.isfile('/etc/security/limits.conf'):
        coreValue = helpers.get_stdout(
            'grep -Exic "hard[[:blank:]]+core[[:blank:]]+0" /etc/security/limits.conf'
        ).strip()
        coreValueDefault = helpers.get_stdout(
            'grep -Exic "\\*[[:blank:]]+hard[[:blank:]]+core[[:blank:]]+0" /etc/security/limits.conf'
        ).strip()
    dumpableValue = helpers.get_stdout('sysctl -n fs.suid_dumpable').strip()
    if (coreValue == '1' or coreValueDefault == '1') and (
        dumpableValue == '0' or dumpableValue == '2'
    ):
        print('\033[32mRestricted\033[m\n')
    else:
        print('\033[31mNot Restricted\033[m\n')
