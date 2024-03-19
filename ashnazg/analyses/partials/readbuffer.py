from ..analyses import Vulnerability, partial

from ..functions import isLocal, isParameter, getLocal
from ..types import ConcreteValue
from ashnazg import Connection

from dorat.schema import DoratFunction, DoratVariable

import logging

logger = logging.getLogger(name=__name__)

# This partial detects if there is a buffer which
# is read from.
@partial
class ReadBuffer(Vulnerability):
    name="ReadBuffer"

    def __init__(self,
                 read_call : DoratFunction,
                 buffer : DoratVariable,
                 bufferSize : int):
        self.write_call : DoratFunction = write_call
        self.read_call : DoratFunction = read_call
        self.buffer : DoratVariable = buffer
        self.bufferRead : int = bufferSize
    
    @staticmethod
    def detect_all(context, function : DoratFunction, program, options):
        result = []
        for call in function.calls:
            try:
                if call.funcName in ["write"]:
                    args = call.arguments
                    if args[0] == "1" and isLocal(args[1], function):
                        bufferSize = int(args[2], 16)
                        bufferVar = getLocal(args[1], function)
                        result.append(ReadBuffer(
                            read_call=call,
                            buffer=bufferVar,
                            bufferSize=bufferSize))
                # TODO: Do we want to do this here, or do we
                # subclass in some sense
                if call.funcName in ["puts"]:
                    args = call.arguments
                    if isLocal(args[0], function):
                        bufferVar = getLocal(args[1], function)
                        result.append(ReadBuffer(
                            read_call=call,
                            buffer=bufferVar,
                            bufferRead=None))
            except Exception as e:
                logger.log(logging.ERROR, e)
                continue
        return result

    def exploit(self, conn : Connection, targetValue : ConcreteValue):
        self.write(conn, targetValue)
    
    def write(self, conn : Connection, targetValue : ConcreteValue):
        #TODO: detect if we're currently already in the function.
        if len(targetValue) > self.bufferSize:
            raise Exception(f"Requested Concrete Value '{targetValue}' has length {len(targetValue)} which execeeds {self.bufferSize}")
        conn.navigate(self.write_call.address)
        conn.send(targetValue)
    
    def bufferSize(self):
        return self.bufferSize#
