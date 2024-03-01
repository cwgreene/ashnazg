from ..analyses import Vulnerability, partial

from ..functions import isLocal, isParameter, getLocal
from ..types import ConcreteValue
from ashnazg import Connection

from dorat.schema import DoratFunction, DoratVariable

import logging

logger = logging.getLogger(name=__name__)

# This partial detects if there is a buffer which
# is written to that allows for string which is not null terminated.
@partial
class UnterminatedBuffer(Vulnerability):
    name="UnterminatedBuffer"

    def __init__(self, write_call : DoratFunction, buffer : DoratVariable, bufferSize : int):
        self.write_call : DoratFunction = write_call
        self.buffer : DoratVariable = buffer
        self.bufferSize : int = bufferSize
    
    @staticmethod
    def detect(context, function : DoratFunction, program, options, debug=False):
        for call in function.calls:
            try:
                print(call)
                if call.funcName in ["read"]:
                    args = call.arguments
                    # TODO: buffer doesn't need to be local
                    if args[0] == "0" and isLocal(args[1], function):
                        bufferSize = int(args[2], 16)
                        bufferVar = getLocal(args[1], function)
                        return UnterminatedBuffer(
                            write_call=call,
                            buffer=bufferVar,
                            bufferSize=bufferSize)
            except Exception as e:
                logger.log(logging.ERROR, e)
                continue
        return None

    def exploit(self, conn : Connection, targetValue : ConcreteValue):
        self.write(conn, targetValue)
    
    def write(self, conn : Connection, targetValue : ConcreteValue):
        #TODO: detect if we're currently already in the function.
        if len(targetValue) > self.bufferSize:
            raise Exception(f"Requested Concrete Value '{targetValue}' has length {len(targetValue)} which execeeds {self.bufferSize}")
        conn.navigate(self.write_call.address)
        conn.send(targetValue)
    
    def bufferSize(self):
        return self.bufferSize
