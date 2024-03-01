import ashnazg

import pytest

from ashnazg.tlldb import TLLDB
from ashnazg.analyses.partials.unterminatedbuffer import UnterminatedBuffer

def test_unterminated_buffer_detect():
    nazg = ashnazg.Ashnazg(binary="test_data/buffers/unterminated_buffer")
    func = nazg.find_function("main")
    result = nazg.detect_vuln(UnterminatedBuffer, func)
    assert result != None

#@pytest.mark.skip("Need to implement and test tlldb functions")
def test_unterminated_buffer_write():
    nazg = ashnazg.Ashnazg(binary="test_data/buffers/unterminated_buffer")
    func = nazg.find_function("main")
    buffer = nazg.detect_vuln(UnterminatedBuffer, func)
    assert isinstance(buffer, UnterminatedBuffer)
    conn = nazg.connect()
    tlldb = TLLDB(nazg.binaryname, conn.pid())
    bp_after = tlldb.set_breakpoint_after_call(buffer.write_call)
    print("bp_after", bp_after)
    if bp_after == None:
        raise Exception(f"Failed to set breakpoint at {hex(buffer.write_call.address)}.")
    buffer.write(conn, b"chicken")
    print(buffer.buffer.stackOffset)
    tlldb.await_breakpoint(bp_after)
    result = tlldb.read_stack_memory(buffer.buffer.stackOffset, len(b"chicken"))
    assert b"chicken" == result