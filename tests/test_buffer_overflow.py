import nose

import ashnazg

from ashnazg.analyses import StackBufferOverflowVulnerability

def test_can_detect_buffer_overflow():
    ash = ashnazg.Ashnazg("test_data/nocanarypie/nocanarypie")
    vulns = ash.find_vulnerable_functions()
    nose.tools.ok_(len(vulns) >= 1, "No vulnerabilities found in nocanarypie!")
    sb_types = [v for v in vulns if isinstance(v, StackBufferOverflowVulnerability) ]
    nose.tools.ok_(len(sb_types) >= 1, "Could not find a StackBufferOverflowVulnerability")

def test_can_exploit_buffer_overflow():
    ash = ashnazg.Ashnazg("test_data/nocanarypie/nocanarypie")
    vulns = ash.find_vulnerable_functions()
    nose.tools.ok_(len(vulns) >= 1, "No vulnerabilities found in nocanarypie!")
    sb_types = [v for v in vulns if isinstance(v, StackBufferOverflowVulnerability) ]
    nose.tools.ok_(len(sb_types) >= 1, "Could not find a StackBufferOverflowVulnerability")
