import gdb

#to enable this commadn you need to source this file form gdb console or gdninit
# source /path/to/this/file.py

class GoBack(gdb.Command):
    def __init__ (self):
        super(GoBack,self).__init__(
            "goback",
            gdb.COMMAND_OBSCURE,
            gdb.COMPLETE_NONE,
            True
        )


    def invoke(self, args, from_tty):
        gdb.execute("signal SIGSTOP")
        gdb.execute("detach")
        gdb.execute("quit")


GoBack()
