import ashnazg
from ashnazg.analyses.partials import UnterminatedBuffer

def test_canary():
    nazg = ashnazg.Ashnazg(binary="test_data/buffers/unterminated_buffer")
    func = nazg.find_function("main")
    buffer : UnterminatedBuffer = nazg.detect_vuln(UnterminatedBuffer, func)
    
    conn = nazg.connect()

    conn.navigate(buffer.write_call.address)
    conn.send(b"a"*buffer.buffer.size)

    