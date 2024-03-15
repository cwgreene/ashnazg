import ashnazg

def test_connection():
    nazg = ashnazg.Ashnazg("test_data/random/random")
    r = nazg.connect()
    res = r.recvuntil(b"Secret")
    assert res == b"Secret"

# TODO: This is really testing too much about canaries
def test_resolve():
    nazg = ashnazg.Ashnazg("test_data/canary/canary_example_putchar")
    conn = nazg.connect()
    conn.navigate(nazg.lookup("gets"))
    canary = conn.transcription[-9:-1]
    result = conn.resolve(conn.canary)
    #conn.sendline(b"")
    print(result)
    print(canary)
    assert result == canary
