import ashnazg

def test_connection():
    nazg = ashnazg.Ashnazg("test_data/random/random")
    r = nazg.connect()
    res = r.recvuntil(b"Secret")
    assert res == b"Secret"