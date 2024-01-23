import ashnazg
from ashnazg.analyses.partials.unterminatedbuffer import UnterminatedBuffer

def test_unterminated_buffer_detect():
    nazg = ashnazg.Ashnazg(binary="test_data/buffers/unterminated_buffer")
    func = nazg.find_function("main")
    result = nazg.detect_vuln(UnterminatedBuffer, func)
    assert result != None

def test_unterminated_buffer_write():
    nazg = ashnazg.Ashnazg(binary="test_data/buffers/unterminated_buffer")
    func = nazg.find_function("main")
    buffer = nazg.detect_vuln(UnterminatedBuffer, func)
    assert isinstance(buffer, UnterminatedBuffer)
    conn = nazg.connect()
    buffer.write(conn, b"chicken")
