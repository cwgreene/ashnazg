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

class Model:
    def __init__(self, simgr):
        self.stdout_pos = 0
        self.stdin_pos = 0
        self.state = simgr.active[0]
        self.simgr = simgr

    def explore_to(self, find):
        self.simgr.explore(find=find)
        # Check if we found anything
        # TODO: throw a more appropriate exception
        if not self.simgr.found:
            raise Exception("Could not find path to '{}' from '{}'".format(hex(find), self.state))
        self.state = self.simgr.found[0]

        # set us up for the future
        self.simgr.active.clear()
        self.simgr.found.clear()
        self.simgr.active.append(self.state)
        # we're good for more navimagation!

    def get_output(self):
        # TODO: validate that dumps actually collapses the output
        # otherwise we could mutate as the state evolves further.
        stdout = self.state.posix.dumps(1)
        result = stdout[self.stdout_pos:]
        self.stdout_pos = len(result)
        return result
    
    def get_input(self):
        # TODO: validate that dumps actually collapses the input
        # otherwise we could mutate as the state evolves further.
        stdin = self.state.posix.dumps(0)
        result = stdin[self.stdin_pos:]
        self.stdin_pos = len(result)
        return result
    
    def send(self, s):
        if type(s) == str:
            s = bytes(s, 'utf8')
        self.stdin_pos += len(s) # we're assuming we're at the end... possibly bad assumption
        self.state.posix.stdin.content.append(s)

    def sendline(self, s):
        if type(s) == str:
            s = bytes(s, 'utf8')
        self.send(s+b"\n")
    
    def get_state(self):
        return self.state

class Ashnazg:
    def __init__(self, binary : str, libc : str = None, vuln_args : dict = None):
        if libc == None:
            libc = DEFAULT_LIBC
        if vuln_args == None:
            vuln_args = {}
        self.binaryname = binary
        self.binary_elf = pwn.ELF(binary)
        self.libc_elf = pwn.ELF(libc)
        self.angr_project = angr.Project(binary, auto_load_libs=False)
        self.db = BinaryDb()
        self.vuln_args = vuln_args

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
        for vuln in analyses.ANALYSES:
            ashnazg_log.info(f"Analyzing {vuln.name}")
            for function in program["functions"]:
                ashnazg_log.info(f"  Analyzing {vuln.name}:{function['name']}")
                result = vuln.detect(Context(self.binary_elf, self.libc_elf), function, program['functions'], self.vuln_args)
                if result:
                    ashnazg_log.info(f"  FOUND vulnerable function {function['name']}")
                    vulns.append(result)
        return vulns


    def connect(self, remote=None, debug=False):
        if remote:
            ashnazg_log.info(f"Connecting to {remote}")
            self.connection = Connection(self, remote=remote) 
        else:
            ashnazg_log.info(f"Connecting to program '{self.binaryname}'")
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
        entry_state = nazg.angr_project.factory.entry_state()
        entry_state.options.add(angr.options.UNICORN)
        entry_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        
        self.model = Model(nazg.angr_project.factory.simulation_manager(entry_state))

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
        ashnazg_log.info(f"{function_addr},{type(function_addr)}")
        ashnazg_log.info(f"Navigating program to {hex(function_addr)} from {self.model.get_state()}")
        # find inputs to navigate to target function
        ashnazg_log.info(f"Simulating program locally to determine navigation input.")

        # proposed change
        self.model.explore_to(find=function_addr) # raises exception if it can't find the target state
        expected_output = self.model.get_output() # lets model know how much we've used
        found_input = self.model.get_input() # consumes input

        # Send the concretized input to the target
        if found_input:
            ashnazg_log.info(f"Sending navigation input to target: {found_input}")
            self.conn.send(found_input)
        
        # If there is any expected output (to get here in the first place), recieve it.
        # TODO: This won't work if the expected output is variable in length.
        # TODO: We need to update the model to mark where in stdout we are.
        if expected_output:
            ashnazg_log.info(f"Capturing expected output: {expected_output}",)
            result = self.conn.recv(len(expected_output), timeout=5) # TODO: make timeout runtime param
            if result != expected_output:
                ashnazg_log.error(f"Failed to get expected output!")
                actual = self.conn.recv()
                raise Exception("Failed to get expected output, got {actual} instead")
            ashnazg_log.info(f"Got expected output {result}")    
            self.transcription += result

    def exploit(self, vuln, assume=None):
        vuln.exploit(self)

    def send(self, bs):
        return self.conn.send(bs)

    def recv(self):
        return self.conn.recv()

    def recvuntil(self, bs):
        return self.conn.recvuntil(bs)

    def interactive(self):
        self.conn.interactive()
