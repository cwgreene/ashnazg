import lldb
import os

from pwn import ELF
from dorat.schema import DoratCall

import logging

tlldb_log = logging.getLogger("tlldb")

# Test LLDB
# Class for use in testing behavior of exploited code.
# Intended for testing, should not be used in exploit logic.
class TLLDB:
    INITIALIZED = False
    WAIT_TIMEOUT = 1
    def __init__(self, path : str, pid : int = None):
        if TLLDB.INITIALIZED == False:
            os.environ["LLDB_DEBUGSERVER_PATH"] = "/usr/bin/lldb-server-14"
            lldb.SBDebugger.Initialize()
            TLLDB.INITIALIZED = True
        self.path : str = path
        self.binary =  ELF(path)
        self.debugger : lldb.SBDebugger = lldb.SBDebugger.Create()
        self.debugger.SetAsync(True)
        self.target : lldb.SBTarget = self.debugger.CreateTargetWithFileAndArch(path, lldb.LLDB_ARCH_DEFAULT)
        self.listener : lldb.SBListener = self.debugger.GetListener()
        error : lldb.SBError = lldb.SBError()
        
        # Connect to running process
        if pid:
            self.process : lldb.SBProcess = self.target.AttachToProcessWithID(self.listener, pid, error)
        else:
            self.process : lldb.SBProcess = self.target.LaunchSimple(None, None, os.getcwd())
            self.pid : int = self.process.GetProcessID()
        if not error.Success():
            raise Exception(f"Could not attach to {pid}:", error.description)

    def _compute_instruction_after_call(self, address):
        # read two instructions from memory
        instructions : lldb.SBInstructionList = self.target.ReadInstructions(lldb.SBAddress(address, self.target), 2)

        insn : lldb.SBInstruction = instructions[1]
        addr : lldb.SBAddress = insn.addr
        return addr.GetLoadAddress(self.target)
            

    def set_breakpoint_after_call(self, call : DoratCall ) -> lldb.SBBreakpoint:
        after_address = self._compute_instruction_after_call(call.address)
        print(hex(after_address))
        return self.target.BreakpointCreateByAddress(after_address)

    def set_breakpoint_at(self, addr : int):
        return self.target.BreakpointCreateByAddress(addr)
    
    # TODO: Need tests around this
    def read_stack_memory(self, offset, size):
        thread : lldb.SBThread = self.process.GetSelectedThread()
        frame : lldb.SBFrame = thread.frames[0]
        if not self.process.is_alive:
            pid = self.process.GetProcessID()
            status = open(f"/proc/{pid}/status").read()
            raise Exception(f"Attempted to read stack of process ({self.process.GetProcessID()}) that is not alive.\n{status}")
        error_ref = lldb.SBError()
        frame_offset = offset + 8 # this is probably architecture + compiler specific
        return self.process.ReadMemory(frame.fp + frame_offset, size, error_ref)
    
    def set_breakpoint_at_call_in_func(self, func : str, call : str, index=0):
        pass

    def await_breakpoint(self, bp=None, timeout_s=10):
        self.resume() # This is the only time we should probably be resuming
        return self.handle_events()
    
    # Maybe Private?
    def resume(self) -> lldb.SBError:
        err = self.process.Continue()
        return err
    
    def thread_register(self, register):    
        thread : lldb.SBThread = self.process.GetSelectedThread()
        frame : lldb.SBFrame = thread.GetSelectedFrame()
        register : lldb.SBValue = frame.register[register]
        return int(register.value, 16)

    def handle_events(self):
        error = lldb.SBError()

        listener = self.debugger.GetListener()
        # sign up for process state change events
        stop_idx = 0
        done = False
        while not done:
            event = lldb.SBEvent()
            print(event)
            if listener.WaitForEvent(self.WAIT_TIMEOUT, event):
                if lldb.SBProcess.EventIsProcessEvent(event):
                    state = lldb.SBProcess.GetStateFromEvent(event)
                    if state == lldb.eStateInvalid:
                        # Not a state event
                        tlldb_log.log(logging.DEBUG, 'process event = %s' % (event))
                    else:
                        tlldb_log.log(logging.DEBUG, "process state changed event: %s" % (lldb.SBDebugger.StateAsCString(state)))
                        if state == lldb.eStateStopped:
                            tlldb_log.log(logging.DEBUG, 'event = %s' % (event))
                            done = True
                            break
                        elif state == lldb.eStateExited:
                            tlldb_log.log(logging.DEBUG, 'event = %s' % (event))
                            done = True
                        elif state == lldb.eStateCrashed:
                            tlldb_log.log(logging.DEBUG, 'event = %s' % (event))
                            done = True
                        elif state == lldb.eStateDetached:
                            tlldb_log.log(logging.DEBUG, 'event = %s' % (event))
                            done = True
                        elif state == lldb.eStateRunning:
                            tlldb_log.log(logging.DEBUG, 'event = %s' % (event))
                            pass
                        elif state == lldb.eStateUnloaded:
                            tlldb_log.log(logging.DEBUG, 'event = %s' % (event))
                            continue
                        elif state == lldb.eStateConnected:
                            tlldb_log.log(logging.DEBUG, 'event = %s' % (event))
                            pass
                        elif state == lldb.eStateAttaching:
                            tlldb_log.log(logging.DEBUG, 'event = %s' % (event))
                            pass
                        elif state == lldb.eStateLaunching:
                            tlldb_log.log(logging.DEBUG, 'event = %s' % (event))
                            pass
                else:
                    tlldb_log.log(logging.DEBUG, 'event = %s' % (event))
            else:
                # timeout waiting for an event
                tlldb_log.log(logging.DEBUG, "no process event for %u seconds, killing the process..." % (self.WAIT_TIMEOUT))
                done = True
        return event, state
