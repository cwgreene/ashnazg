import ashnazg

import pytest

from ashnazg.tlldb import TLLDB
from ashnazg.analyses.partials.unterminatedbuffer import UnterminatedBuffer

def test_unterminated_buffer_detect():
    nazg = ashnazg.Ashnazg(binary="test_data/buffers/unterminated_buffer")
    func = nazg.find_function("main")
    result = nazg.detect_vuln(UnterminatedBuffer, func)
    assert result != None

# Verify that buffer.write works.
def test_unterminated_buffer_write():
    # Find a buffer which is not terminated.
    nazg = ashnazg.Ashnazg(binary="test_data/buffers/unterminated_buffer")
    func = nazg.find_function("main")
    buffer = nazg.detect_vuln(UnterminatedBuffer, func)
    assert isinstance(buffer, UnterminatedBuffer)
    # Connect to instance and attach debugger for verification
    conn = nazg.connect()
    tlldb = TLLDB(nazg.binaryname, conn.pid())

    # setup breakpoint immediately after write call
    bp_after = tlldb.set_breakpoint_after_call(buffer.write_call)
    if bp_after == None:
        raise Exception(f"Failed to set breakpoint at {hex(buffer.write_call.address)}.")
    
    # Write to the discovered buffer
    buffer.write(conn, b"chicken")

    # Wait for write to execute.
    tlldb.await_breakpoint(bp_after)

    # Validate that buffer contains 'chicken'
    result = tlldb.read_stack_memory(buffer.buffer.stackOffset, len(b"chicken"))
    assert b"chicken" == result
