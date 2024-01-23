from ..analyses import Vulnerability, partial

from ..functions import isLocal, isParameter, getLocal
from ..types import ConcreteValue
from ashnazg import Connection

import logging

logger = logging.getLogger(name=__name__)

# This partial detects if there is a buffer which
# is written to that allows for string which is not null terminated.
@partial
class UnterminatedBuffer(Vulnerability):
    name="UnterminatedBuffer"

    def __init__(self, function, buffer : str, bufferSize : int):
        self.function = function
        self.buffer = buffer
        self.bufferSize = bufferSize
    
    @staticmethod
    def detect(context, function, program, options, debug=False):
        for call in function["calls"]:
            try:
                print(call)
                if call["funcName"] in ["read"]:
                    args = call["arguments"]
                    print(args)
                    # TODO: buffer doesn't need to be local
                    if args[0] == "0" and isLocal(args[1], function):
                        bufferSize = int(args[2], 16)
                        return UnterminatedBuffer(
                            function=function,
                            buffer=getLocal(args[1], function),
                            bufferSize=bufferSize)
            except Exception as e:
                logger.log(logging.ERROR, e)
                continue
        return None

    def exploit(self, conn : Connection, targetValue : ConcreteValue):
        #TODO: detect if we're currently already in the function.
        if len(targetValue) > self.bufferSize:
            raise Exception(f"Requested Concrete Value '{targetValue}' has length {len(targetValue)} which execeeds {self.bufferSize}")
        conn.navigate(self.function)
        conn.send(targetValue)
    
    def bufferSize(self):
        return self.bufferSize