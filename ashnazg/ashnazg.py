import logging
import os
import subprocess
import json

import angr
import claripy
import pwn
import smrop

from typing import List, Tuple
# for forward references
from __future__ import annotations

from smrop import BinaryDb
from dorat.schema import DoratProgram, DoratFunction
from .analyses import Vulnerability

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
    def __init__(self, binary : str, libc : str = DEFAULT_LIBC, vuln_args : dict = None, debug=False):
        """Constructs main object that tracks various information for exploiting the target binary.

        Args:
            binary (str): Path to binary.
            libc (str, optional): Path to libc to use. Defaults to "/lib/x86_64-linux-gnu/libc.so.6".
            vuln_args (dict, optional): Args to be passed to vulnerability detection. Defaults to None.
                    TODO: Rethink this.
            debug (bool, optional): Whether to use gdb when executing. Defaults to False.
        """
        if vuln_args == None:
            vuln_args = {}
        self.binaryname = binary
        self.binary_elf = pwn.ELF(binary)
        self.libc_elf = pwn.ELF(libc)
        self.project = angr.Project(binary, auto_load_libs=False)
        self.db = BinaryDb()
        self.vuln_args = vuln_args
        self.debug = debug
    
    def _doratprogram(self) -> DoratProgram:
        # check function database
        if self.db.check(self.binaryname, 'dorat'):
            ashnazg_log.info(f"Found entry for '{self.binaryname}' in BinaryDb")
            program = self.db.get(self.binaryname, "dorat")
        else:
            ashnazg_log.info(f"No entry for '{self.binaryname}' in BinaryDb, invoking dorat to generate")
            program = call_dorat(self.binaryname)
            self.db.add(self.binaryname, 'dorat', program)
            self.db.save()
        return DoratProgram(program)

    def is_navigable(self, function: DoratFunction) -> bool:
        # TODO: This check is expensive.
        try:
            conn = self.connect() 
            conn.navigate(function.address) 
        except Exception as e:
            return False
        return True

    def find_vulnerable_functions(self, debug=False) -> List[Vulnerability]:
        program = self._doratprogram()
        vulns = []  
        # analyze functions for call
        for vuln in analyses.toplevel():
            ashnazg_log.info(f"Analyzing {vuln.name}")
            for function in program.functions:
                result = self.detect_vuln(vuln, function)
                if result:
                    if self.is_navigable(function):
                        ashnazg_log.info(f"  FOUND vulnerable function {function.name}: {str(result)}")
                        vulns.append(result)
                    else:
                        ashnazg_log.info(f"  NON-NAVIGABLE vulnerable function {function.name}: {str(result)}")
        return vulns

    def functions(self) -> List[DoratFunction]:
        program = self._doratprogram()
        return program.functions

    def find_function(self, name) -> DoratFunction:
        for function in self.functions():
            if function.name == name:
                return function

    def detect_vuln(self, vuln, function, debug=False) -> Vulnerability:
        program = self._doratprogram()
        ashnazg_log.info(f"  Analyzing {vuln.name}:{function.name}")
        result = vuln.detect(Context(self.binary_elf, self.libc_elf),
                                     function,
                                     program.functions,
                                     self.vuln_args,
                                     debug=debug)
        return result

    def connect(self, remote : Tuple[str,int] = None, debug : bool = False) -> Connection:
        if remote:
            ashnazg_log.info(f"Connecting to {remote}")
            connection = Connection(self, remote=remote) 
        else:
            ashnazg_log.info(f"Connecting to program '{self.binaryname}'")
            connection = Connection(self, binary=self.binaryname, debug=debug) 
        return connection

    def lookup(self, symbolname : str) -> int:
        """Looks up address of symbol name. Plt is resolved first.

        Args:
            symbolname (str): symbol name to lookup.

        Raises:
            Exception: Failure to find symbol

        Returns:
            int: address (or value) of symbol.
        """        
        if symbolname in self.binary_elf.plt:
            return self.binary_elf.plt[symbolname]
        if symbolname in self.binary_elf.symbols:
            return self.binary_elf.symbols[symbolname]
        raise Exception("Could not find symbol {}".format(symbolname))

class Connection:
    def __init__(self, 
            nazg : Ashnazg, 
            binary : str = None, 
            remote : Tuple[str, int] = None,
            debug : bool = False):
        """Connection - Creates a connection, either remotely or to the process,
        which is running the associated nazg binary. This connection exposes
        most of the pwn tools connection interface.

        Args:
            nazg (Ashnazg): The associated Ashnazg object with the target.
            binary (str, optional): path to binary file. Defaults to None.
                                    TODO: rename this "local" and a boolean
                                    and just use nazg.binary.
            remote (str, optional): remote to connect to. Defaults to None.
            debug (bool, optional): create process with gdb. Defaults to False.
        """        
        if binary is None and remote is None:
            raise TypeError("{}: either 'binary' or 'remote' must be specified"
                .format(self.__name__))
        # setup simulation manager
        for symbol in ["gets", "fread"]:
            if symbol in nazg.binary_elf.symbols:
                nazg.project.hook_symbol('gets', simprocedures.gets())
                nazg.project.hook_symbol('fread', simprocedures.fread())
                nazg.project.hook_symbol('putchar', simprocedures.putchar())
        # symbolicize the canary. We should really extract out some of this into a more
        # generic "Known Unknowns" associated with the connection.
        self.canary = claripy.BVS("canary", 8*8)

        entry_state = nazg.project.factory.entry_state()
        canary_offset = entry_state.registers.load("fs")+0x28
        entry_state.memory.store(canary_offset, self.canary)
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
        
    def pid(self):
        if isinstance(self.conn, pwn.process):
            return self.conn.pid

    def navigate(self, function_addr):
        """Navigates to provided function address. 'Navigate' implies both
        the simulation and the connection are directed to the specified address.
        If the real connection is not stopped (by waiting on input for example)
        it will obviously continue on past that point.

        Args:
            function_addr (int): target address

        Raises:
            Exception: if no path to the target address can be found.
        """        
        ashnazg_log.info(f"Navigating program to {hex(function_addr)} from {self.active_state}")
        # find inputs to navigate to target function
        ashnazg_log.info(f"Simulating program locally to determine navigation input.")
        self.simgr.explore(find=function_addr)
        if not self.simgr.found:
            raise Exception("Could not find path to '{}'".format(hex(function_addr)))
        
        # TODO: We're cheating a bit here and assuming that all states that lead here
        # produce the same length of observed output. This works for a suprising number of situations
        # but what we ultimately need to do is have navigate use the output and at the very
        # least collapse to a consistent state.
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
        
        # TODO: Using `len` here is a hack. See above
        current_output = self.active_state.posix.dumps(1) 
        expected_output = found_state.posix.dumps(1)[len(current_output):]

        # Here we use the predicted output to figure out how many bytes
        # we need to read from the channel. This will get complicated
        # if there are multiple paths to this location with different output
        # lengths. This can happen when the output is random.
        if expected_output:
            ashnazg_log.info(f"Capturing expected output: {expected_output}")
            actual_output = self.conn.recv(len(expected_output))
            self.transcription += actual_output
            ashnazg_log.info(f"Captured: {actual_output}")
        
        # Updater State
        self.sim_set_state(found_state)
        ashnazg_log.info(f"Updated state {self.simgr.active}")
    
    def resolve(self, variable : claripy.BV) -> bytes:
        """Compares self.transcription with model and attempts to resolve the provided variable based on that comparison.

            TODO: this always returns either a concrete value
            or an exception even if there is freedom in the result.
            So if you ask "what is the canary" without any reason
            to know it, this function unfortunately will "resolve"
            the symbolic value to something consistent with what is
            known, which is nothing, which means it can return anything. 

        Args:
            variable (claripy.BV): variable whose value we will extract based on observation.
        Raises:
            claripy.UnsatError: if the model of program state is inconsistent with output.
                                This can happen when the output contains unmodeled detritus
                                from the stack or heap caused by unfaithful simprocedures.

        Returns:
            bytes: bytes of evaluated variable
        """
        solver = self.active_state.solver
        acc = claripy.BVS("", 0)
        for bv, bv_length in self.active_state.posix.stdout.content:
            acc = acc.concat(bv)
        solver.add(self.transcription == acc)
        return solver.eval(variable).to_bytes(variable.size()//8, "big") # note this will resolve to *something* unless it is impossible

    # TODO:
    # Is scout really necessary?
    # can we just call navigate with the template?
    def scout(self, addr : int, template_input: List[claripy.BV]):
        """Similar to navigate, but we don't update the connection or the model. We just find a state
        and return the needed input to reach it.

        Args:
            function_addr (int): address to scout to.
            template_input (List[claripy.BV]): list of bitvectors that constrain input. 

        Raises:
            Exception: If path to address cannot be found.

        Returns:
            bytes: bytes of input that will reach the provided adderss. 
        """        
        current_input = self.active_state.posix.dumps(0)
        ashnazg_log.info(f"Scouting program to {hex(addr)} from {self.active_state}")
    
        # clone current state and create simgr
        scout_state = self.active_state.copy()
        scout_state.posix.stdin.content += [claripy.Concat(*template_input)]
        ashnazg_log.info(f"{scout_state.posix.stdin.content}")
        simgr = self.nazg.project.factory.simulation_manager(scout_state)

        # find inputs to navigate to target function
        ashnazg_log.info(f"Simulating program locally to determine scout input.")
        simgr.explore(find=addr)
        if not simgr.found:
            raise Exception("Could not scout path to '{}'".format(hex(addr)))
        found_state = simgr.found[0]
        found_input = found_state.posix.dumps(0)[len(current_input):]

        return found_input

    def sim_set_state(self, state: angr.sim_state.SimState):
        """Set simulator to provided state.

        Args:
            state (_type_): _description_
        """        
        self.simgr = self.nazg.project.factory.simulation_manager(state)
        self.active_state = state

    def exploit(self, vuln : Vulnerability, assume : List=None):
        """Perform exploit.

        Args:
            vuln (Vulnerability): Vulnerability instance to exploit.
            assume (_type_, optional): . Defaults to None.
        """        
        return vuln.exploit(self)

    def sim_sendline(self, data : bytes, *args, **kwargs):
        """Send data to simulation as input. Append a newline.

        Args:
            data (bytes): bytes to send.
        """        
        ashnazg_log.info(f"Sending input '{data}' ({len(data)}) at {self.active_state}")
        stdin = self.active_state.posix.stdin
        data += b"\n"
        stdin.content.append((claripy.BVV(data), len(data)))
    
    def sim_send(self, data, *args, **kwargs):
        """_summary_

        Args:
            data (_type_): _description_
        """        
        ashnazg_log.info(f"Sending input '{data}' ({len(data)}) at {self.active_state}")
        stdin = self.active_state.posix.stdin
        stdin.content.append((claripy.BVV(data), len(data)))

    def send(self, *args, **kwargs):
        self.sim_send(*args,**kwargs)
        res = self.conn.send(*args, **kwargs)
        if hasattr(self.conn, "stdin"):
            self.conn.stdin.flush()

    def recv(self, *args, **kwargs):
        """Proxy to pwntools.

        Returns:
           bytes : data from connection.
        """
        return self.conn.recv(*args, **kwargs)

    def recvuntil(self, *args, **kwargs):
        """Proxy to pwntools.

        Returns:
            bytes: data
        """        
        return self.conn.recvuntil(*args, **kwargs)

    def interactive(self):
        """Proxy to pwntools.
        """        
        self.conn.interactive()
