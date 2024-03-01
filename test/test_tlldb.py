from ashnazg.tlldb import TLLDB

import pwn
import time
import lldb

import pytest

def enumerateStates():
    for attr in dir(lldb):
        if attr.startswith('eState'):
            print(attr, getattr(lldb, attr))

def test_lldb_init_pwn():
    READ_LOCATION = 0x40119b
    PUTS_LOCATION = 0x4011aa
    path = "./test_data/tlldb/simple_lldb"
    p = pwn.process(path)
    tlldb = TLLDB(path, p.pid)
    thread : lldb.SBThread = tlldb.process.GetSelectedThread()
    for frame in thread.frames:
        addr : lldb.SBAddress = frame.addr
        print(addr, hex(addr.GetLoadAddress(tlldb.target)))
        # *sigh* this doesn't work because the above gives us the return
        # address, so the address *after* the current one.
    # process is probably currently at read step

    assert tlldb.process.GetProcessID() == p.pid
    res = tlldb.set_breakpoint_at(PUTS_LOCATION)

    p.send(b"d\n") # Process is still blocked
    event, state = tlldb.await_breakpoint()
    assert state == lldb.eStateStopped
    assert tlldb.thread_register("rip") == PUTS_LOCATION
    tlldb.resume() # Process will now resume
    assert p.recvline() == b"Hello world!\n" # Should we automatically resume processes prior to recvline?