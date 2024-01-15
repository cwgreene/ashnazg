from ..analyses import Vulnerability, partial

from ..functions import isLocal, isParameter, getLocal
from ..types import ConcreteValue
from ....ashnazg import Connection

# This partial detects if there is a buffer which
# is written to that allows for string which is not null terminated.
@partial
class UnterminatedBuffer(Vulnerability):
    def __init__(self, function, buffer):
        self.function = function
        self.buffer = buffer
    
    @staticmethod
    def detect(context, function, program, options, debug=False):
        for call in function["calls"]:
            try:
                if call["funcName"] in ["read"]:
                    args = call["args"]
                    # TODO: buffer doesn't need to be local
                    if args[0] == "0" and isLocal(args[1]):
                        return UnterminatedBuffer(
                            function=function,
                            buffer=args[1])
            except:
                continue
        return None

    def exploit(self, conn : Connection, targetValue : ConcreteValue):
        #TODO: detect if we're currently already in the function.
        conn.navigate(self.function)
        conn.send(targetValue)