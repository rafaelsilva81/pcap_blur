import sys


class StdoutInterceptor:
    def __init__(self, stdout):
        self.original_stdout = stdout

    def write(self, data):
        # Set a flag or condition to check for a breakpoint
        self.debug_write = True
        self.original_stdout.write(data)

    def flush(self):
        self.original_stdout.flush()

    def __getattr__(self, attr):
        return getattr(self.original_stdout, attr)


sys.stdout = StdoutInterceptor(sys.stdout)
