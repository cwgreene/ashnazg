from ..analyses import Vulnerability, partial

from ..functions import isLocal, isParameter, getLocal
from ..types import ConcreteValue
from .buffer import Buffer
from ashnazg import Connection

from dorat.schema import DoratFunction, DoratVariable

import logging

logger = logging.getLogger(name=__name__)

# This partial detects if there is a buffer which
# is read from.
class ReadBuffer(Buffer):
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
    
    def read(self, conn : Connection, targetValue : ConcreteValue):
        #TODO: detect if we're currently already in the function.
        conn.navigate(self.read_call.address)
        conn.recv()
    
    def bufferSize(self):
        return self.bufferSize#
