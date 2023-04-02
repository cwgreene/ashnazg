import nose

import ashnazg
import logging
ashnazg_log = logging.getLogger("ashnazg")
ashnazg_log.setLevel("DEBUG")

from ashnazg.analyses import StackBufferOverflowVulnerability

def test_can_detect_buffer_overflow():
    ash = ashnazg.Ashnazg("test_data/nocanarypie/nocanarypie")
    vulns = ash.find_vulnerable_functions()
    nose.tools.ok_(len(vulns) >= 1, "No vulnerabilities found in nocanarypie!")
    sb_types = [v for v in vulns if isinstance(v, StackBufferOverflowVulnerability) ]
    nose.tools.ok_(len(sb_types) >= 1, "Could not find a StackBufferOverflowVulnerability")

def test_can_exploit_buffer_overflow():
    nazg = ashnazg.Ashnazg("test_data/nocanarypie/nocanarypie")
    vulns = nazg.find_vulnerable_functions()
    vuln = vulns[0]

    # find a vulnerable function
    vuln = list(nazg.find_vulnerable_functions())[0]

    # begin exploit
    conn = nazg.connect()

    # get the program to the vulnerable function
    # input.
    conn.navigate(vuln.entry())

    # 'GETS' vulnerability can be applied immediately if
    # Binary is neither PIE nor canary. This is
    # automatically detected, but we explicitly assume
    # it here.
    conn.exploit(vuln)

    # clear up any output prior to shell
    _ = conn.recv()

    conn.send(b"echo hello world\n")
    text = conn.recvuntil(b"hello world\n")

    nose.tools.ok_(b"hello world\n" in text, "Failed to execute echo command!")
