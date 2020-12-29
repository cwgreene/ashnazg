import os
import subprocess
import json

import angr
import pwn
import smrop

from smrop import BinaryDb

import analyses

# TODO: Look this up using something less system specific
DEFAULT_LIBC="/lib/x86_64-linux-gnu/libc.so.6"

def call_dorat(binaryname):
    result = {}
    
    proc = subprocess.run(["dorat", "--binary", binaryname, '--script', 'FunctionCalls.java'], stdout=subprocess.PIPE)
    stdout = str(proc.stdout, "utf8")
    return json.loads(stdout)

class Ashnazg:
    def __init__(self, binary : str, libc : str = None):
        if libc == None:
            libc = DEFAULT_LIBC
        self.binaryname = binary
        self.binary_elf = pwn.ELF(binary)
        self.libc_elf = pwn.ELF(libc)
        self.project = angr.Project(binary)
        self.db = BinaryDb()

    def find_vulnerable_functions(self):
        # check function database
        if self.db.check(self.binaryname, 'dorat'):
            program = self.db.get(self.binaryname, "dorat")
        else:
            program = call_dorat(self.binaryname)
            self.db.add(self.binaryname, 'dorat', program)
            self.db.save()
        vulns = []  
        # analyze functions for call
        for function in program["functions"]:
            for vuln in analyses.ANALYSES:
                result = vuln(function, self.binary_elf).detect(function, program['functions'])
                if result:
                    vulns.append(vuln)
        return vulns


    def connect(self, remote=None):
        if remote:
            self.connection = Connection(remote=remote) 
        else:
            self.connection = Connection(binary=self.binary) 
        return self.connection

    def lookup(self, function):
        if function in self.binary_elf.plt:
            return self.binary_elf.plt[function]
        if function in self.binary_elf.symbols:
            return self.binary_elf.symobls[function]
        raise Exception("Could not find function {}".format(function))

class Connection:
    def __init__(self, 
            nazg : Ashnazg, 
            binary : str = None, 
            remote : str = None):
        if binary is None and remote is None:
            raise TypeError("{}: either 'binary' or 'remote' must be specified"
                .format(self.__name__))
        # setup simulation manager
        entry_state = nazg.project.factory.entry_state()
        self.simgr : angr.SimulationManager = nazg.project.factory.simulation_manager(entry_state)

        self.transcription = ""

        if binary:
            self.conn = pwn.process(binary)
        elif remote:
            self.conn = pwn.remote(remote)

    def navigate(self, function ):
        # find inputs to navigate to target function
        self.simgr.explore(self.nazg.lookup(function))
        if not self.simgr.found:
            raise Exception("Could not find path to '{}'".format(function))
        found_state = self.simgr.found[0]
        found_input = found_state.posix.dumps(0)
        self.conn.send(found_input)
        self.transcription += self.recv()

    def exploit(self, vuln, assume):
        vuln.exploit(self)

    def interactive(self):
        self.conn.interactive()