import ashnazg
from ashnazg.analyses.partials import UnterminatedBuffer

# What is this doing? It's half finished, I guess we'll put
# canary leak test here.
def test_canary():
    nazg = ashnazg.Ashnazg(binary="test_data/buffers/unterminated_buffer")
    func = nazg.find_function("main")
    buffer : UnterminatedBuffer = nazg.detect_vulns(UnterminatedBuffer, func)[0]
    
    conn = nazg.connect()

    conn.navigate(buffer.write_call.address)
    conn.send(b"a"*buffer.buffer.size)

    