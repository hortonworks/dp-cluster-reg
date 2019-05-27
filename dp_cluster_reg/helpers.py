import pwd
import os


class BColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    def disable(self):
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''
        self.BOLD = ''
        self.UNDERLINE = ''


class ScriptPrerequisites:
    def satisfied(self):
        if 'root' != self.current_user():
            print BColors.FAIL + 'This script should be executed with the root user.' + BColors.ENDC
            return False
        return True

    def current_user(self):
        return pwd.getpwuid(os.getuid()).pw_name
