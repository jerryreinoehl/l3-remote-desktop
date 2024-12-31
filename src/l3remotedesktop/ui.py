import getpass
import sys


class UI:

    BOLD_BLACK = "1;30"
    BOLD_RED = "1;31"
    BOLD_GREEN = "1;32"
    BOLD_CYAN = "1;36"
    RED = "31"
    GREEN = "32"
    YELLOW = "33"
    BLUE = "34"
    MAGENTA = "35"
    CYAN = "36"

    def __init__(self, debug=False):
        self._debug = debug

    def set_debug(self, enabled: bool):
        self._debug = enabled

    def print(self, s, width=None, color=None, **kwargs):
        if width:
            s = f"{s:>{width}}"

        if color:
            s = f"\x1b[{color}m{s}\x1b[0m"

        print(s, **kwargs)

    def input(self, prompt, **kwargs):
        self.print("??? " + prompt, end="", color=self.MAGENTA, flush=True, **kwargs)
        return input()

    def getpass(self, prompt, **kwargs):
        self.print("??? " + prompt, end="", color=self.MAGENTA, flush=True, **kwargs)
        return getpass.getpass(prompt="")

    def log_request(self, msg, **kwargs):
        if not self._debug:
            return
        self.print(">>> " + msg, color=self.CYAN, **kwargs)

    def log_response(self, msg, **kwargs):
        if not self._debug:
            return
        self.print("<<< " + msg, color=self.YELLOW, **kwargs)

    def log_exec(self, msg, **kwargs):
        if not self._debug:
            return
        self.print("/// " + msg, color=self.BLUE, **kwargs)

    def debug(self, msg, **kwargs):
        if not self._debug:
            return
        self.print(msg, color=self.BLUE, **kwargs)

    def info(self, msg, **kwargs):
        self.print("... " + msg, color=self.GREEN, **kwargs)

    def success(self, msg, **kwargs):
        self.print("*** " + msg, color=self.BOLD_GREEN, **kwargs)

    def error(self, msg):
        self.print("!!! " + msg, color=self.RED, file=sys.stderr)

    def fatal(self, msg, code=1):
        self.error(msg)
        exit(code)
