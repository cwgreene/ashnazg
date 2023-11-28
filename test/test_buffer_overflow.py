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

def exploitbuffer(program):
    nazg = ashnazg.Ashnazg(program)
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

    # So there's a race condition here: when we send input
    # it may go to the nocanary pie process, or it may get
    # passed to the child process [TODO: understand how this works]
    # I think a better option than pausing here is to obtain
    # the process id and wait for it to spawn a subprocess, and
    # *then* send the input.
    for i in range(2):
        conn.send(b"echo hello world\n")
        text = conn.recvuntil(b"hello world\n", timeout=.5)

    nose.tools.ok_(b"hello world\n" in text, "Failed to execute echo command!")

def test_can_exploit_buffer_overflow():
    exploitbuffer("test_data/nocanarypie/nocanarypie")

def test_can_navigate_to_exploit():
    exploitbuffer("test_data/nocanarypie/nocanarypie2")
