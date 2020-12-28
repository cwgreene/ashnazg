import os
import subprocess

import angr
import pwn
import smrop

from smrop import BinaryDb

import analyses

def call_dorat(binaryname):
    result = {}
    
    proc = subprocess.run(["dorat", "--binary", binaryname], stdout=subprocess.PIPE)
    stdout = str(proc.stdout, "utf8")


class Ashnazg:
    def __init__(self, binary : str, libc : str):
        self.binary = binary
        self.binary_elf = pwn.ELF(binary)
        self.project = angr.Project(binary)
        self.db = BinaryDb()

    def find_vulnerable_functions(self):
        # check function database
        if self.db.check(self.binary):
            functions = self.db.get(self.binary, "functions")
        else:
            functions = call_dorat()
            self.db.add(self.binaryname, 'functions', functions)
            self.db.save('functions', functions)
        vulns = []  
        # analyze functions for call
        for function in functions:
            for vuln in analyses.ANALYSES:
                result = vuln.detect(function, functions)
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
        payload = vuln.exploit()



    def interactive(self):
        self.conn.interactive()

class Exploit:
    def __init__(self, conn, payload):
        self.conn = conn
        self.payload = payload

    def execute(self):
        # this is wrong; we need to be able
        # to have
        self.conn.send(self.payload)
