import logging
import os
import subprocess
import json

import angr
import pwn
import smrop

from smrop import BinaryDb

import ashnazg.analyses as analyses

# clean up logging for pwnlib
pwnlog = logging.getLogger('pwnlib')
pwnlog.setLevel('ERROR')

ashnazg_log = logging.getLogger('ashnazg')

# TODO: Look this up using something less system specific
DEFAULT_LIBC="/lib/x86_64-linux-gnu/libc.so.6"

def call_dorat(binaryname):
    result = {}
    dorat = ["dorat", "--binary", binaryname, '--script', 'FunctionCalls.java']
    ashnazg_log.info(f"Invoking Dorat: {dorat}")
    proc = subprocess.run(dorat, stdout=subprocess.PIPE)
    stdout = str(proc.stdout, "utf8")
    return json.loads(stdout)

class Context:
    def __init__(self, binary, libc):
        self.binary = binary
        self.libc = libc

class Ashnazg:
    def __init__(self, binary : str, libc : str = None, options : dict = None):
        if libc == None:
            libc = DEFAULT_LIBC
        self.binaryname = binary
        self.binary_elf = pwn.ELF(binary)
        self.libc_elf = pwn.ELF(libc)
        self.project = angr.Project(binary, auto_load_libs=False)
        self.db = BinaryDb()

    def find_vulnerable_functions(self):
        # check function database
        if self.db.check(self.binaryname, 'dorat'):
            ashnazg_log.info(f"Found entry for '{self.binaryname}' in BinaryDb")
            program = self.db.get(self.binaryname, "dorat")
        else:
            ashnazg_log.info(f"No entry for '{self.binaryname}' in BinaryDb, invoking dorat to generate")
            program = call_dorat(self.binaryname)
            self.db.add(self.binaryname, 'dorat', program)
            self.db.save()
        vulns = []  
        # analyze functions for call
        for function in program["functions"]:
            for vuln in analyses.ANALYSES:
                ashnazg_log.info(f"Analyzing {vuln.name}")
                result = vuln.detect(Context(self.binary_elf, self.libc_elf), function, program['functions'])
                if result:
                    vulns.append(result)
        return vulns


    def connect(self, remote=None, debug=False):
        if remote:
            self.connection = Connection(self, remote=remote) 
        else:
            self.connection = Connection(self, binary=self.binaryname, debug=debug) 
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
            remote : str = None,
            debug : bool = False):
        if binary is None and remote is None:
            raise TypeError("{}: either 'binary' or 'remote' must be specified"
                .format(self.__name__))
        # setup simulation manager
        entry_state = nazg.project.factory.entry_state()
        entry_state.options.add(angr.options.UNICORN)
        entry_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        
        self.simgr : angr.SimulationManager = nazg.project.factory.simulation_manager(entry_state)

        self.nazg = nazg
        self.transcription = b""

        if binary:
            if debug:
                self.conn = pwn.gdb.debug(binary)
            else:
                self.conn = pwn.process(binary)
        elif remote:
            self.conn = pwn.remote(*remote)

    def navigate(self, function_addr):
        # find inputs to navigate to target function
        self.simgr.explore(find=function_addr)
        if not self.simgr.found:
            raise Exception("Could not find path to '{}'".format(hex(function_addr)))
        found_state = self.simgr.found[0]
        found_input = found_state.posix.dumps(0)
        self.conn.send(found_input)
        expected_output = found_state.posix.dumps(1)
        if expected_output:
            self.transcription += self.conn.recv(len(expected_output))

    def exploit(self, vuln, assume=None):
        vuln.exploit(self)

    def send(self, bs):
        return self.conn.send(bs)

    def recv(self):
        return self.conn.recv()

    def interactive(self):
        self.conn.interactive()
