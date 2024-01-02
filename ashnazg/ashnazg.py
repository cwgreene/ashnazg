import logging
import os
import subprocess
import json

import angr
import claripy
import pwn
import smrop

from smrop import BinaryDb

import ashnazg.analyses as analyses

# simprocedures
import ashnazg.simprocedures as simprocedures

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
    def __init__(self, binary : str, libc : str = None, vuln_args : dict = None, debug=False):
        if libc == None:
            libc = DEFAULT_LIBC
        if vuln_args == None:
            vuln_args = {}
        self.binaryname = binary
        self.binary_elf = pwn.ELF(binary)
        self.libc_elf = pwn.ELF(libc)
        self.project = angr.Project(binary, auto_load_libs=False)
        self.db = BinaryDb()
        self.vuln_args = vuln_args
        self.debug = debug

    def find_vulnerable_functions(self, debug=False):
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
                result = vuln.detect(Context(self.binary_elf, self.libc_elf),
                                     function,
                                     program['functions'],
                                     self.vuln_args,
                                     debug=debug)
                if result:
                    ashnazg_log.info(f"  FOUND vulnerable function {function['name']}: {str(result)}")
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
        nazg.project.hook_symbol('gets', simprocedures.gets())
        nazg.project.hook_symbol('fread', simprocedures.fread())
        entry_state = nazg.project.factory.entry_state()
        entry_state.options.add(angr.options.UNICORN)
        entry_state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        
        self.simgr : angr.SimulationManager = nazg.project.factory.simulation_manager(entry_state)
        self.active_state = entry_state

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
        ashnazg_log.info(f"Navigating program to {hex(function_addr)} from {self.active_state}")
        # find inputs to navigate to target function
        ashnazg_log.info(f"Simulating program locally to determine navigation input.")
        self.simgr.explore(find=function_addr)
        if not self.simgr.found:
            raise Exception("Could not find path to '{}'".format(hex(function_addr)))
        found_state = self.simgr.found[0]
        found_input = self.active_state.posix.dumps(0)
        found_input = found_state.posix.dumps(0)[len(found_input):]
        ashnazg_log.info(f"Position is at {found_state.posix.stdin.content} {found_state.posix.stdin.pos}")
        if found_input != b"":
            ashnazg_log.info(f"Sending navigation input to target: {found_input}")
            self.conn.send(found_input)
            if hasattr(self.conn, "stdin"):
                self.conn.stdin.flush()
        else:
            ashnazg_log.info(f"No navigation input needed")
        current_output = self.active_state.posix.dumps(1)
        expected_output = found_state.posix.dumps(1)[len(current_output):]

        if expected_output:
            ashnazg_log.info(f"Capturing expected output: {expected_output}")
            actual_output = self.conn.recv(len(expected_output))
            self.transcription += actual_output
            ashnazg_log.info(f"Captured: {actual_output}")
        # Updater State
        self.sim_set_state(found_state)
        ashnazg_log.info(f"Updated state {self.simgr.active}")
    
    # TODO:
    # Is scout really necessary?
    # can we just call navigate with the template?
    def scout(self, function_addr, template_input):
        current_input = self.active_state.posix.dumps(0)
        ashnazg_log.info(f"Scouting program to {hex(function_addr)} from {self.active_state}")
    
        # clone current state and create simgr
        scout_state = self.active_state.copy()
        scout_state.posix.stdin.content += [claripy.Concat(*template_input)]
        ashnazg_log.info(f"{scout_state.posix.stdin.content}")
        simgr = self.nazg.project.factory.simulation_manager(scout_state)

        # find inputs to navigate to target function
        ashnazg_log.info(f"Simulating program locally to determine scout input.")
        simgr.explore(find=function_addr)
        if not simgr.found:
            raise Exception("Could not scout path to '{}'".format(hex(function_addr)))
        found_state = simgr.found[0]
        found_input = found_state.posix.dumps(0)[len(current_input):]

        return found_input

    def sim_set_state(self, state):
        self.simgr = self.nazg.project.factory.simulation_manager(state)
        self.active_state = state

    def exploit(self, vuln, assume=None):
        vuln.exploit(self)

    def sim_sendline(self, data, *args, **kwargs):
        ashnazg_log.info(f"Sending input '{data}' ({len(data)}) at {self.active_state}")
        stdin = self.active_state.posix.stdin
        data += b"\n"
        stdin.content.append((claripy.BVV(data), len(data)))
    
    def sim_send(self, data, *args, **kwargs):
        ashnazg_log.info(f"Sending input '{data}' ({len(data)}) at {self.active_state}")
        stdin = self.active_state.posix.stdin
        stdin.content.append((claripy.BVV(data), len(data)))

    def send(self, *args, **kwargs):
        self.sim_send(*args,**kwargs)
        res = self.conn.send(*args, **kwargs)
        if hasattr(self.conn, "stdin"):
            self.conn.stdin.flush()

    def recv(self, *args, **kwargs):
        return self.conn.recv(*args, **kwargs)

    def recvuntil(self, *args, **kwargs):
        return self.conn.recvuntil(*args, **kwargs)

    def interactive(self):
        self.conn.interactive()
