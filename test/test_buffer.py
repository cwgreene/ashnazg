import nose

import ashnazg
from ashnazg.analyses.partials.unterminatedbuffer import UnterminatedBuffer

def test_unterminated_buffer_detect():
    nazg = ashnazg.Ashnazg(binary="test_data/buffers/unterminated_buffer")
    func = nazg.find_function("main")
    result = nazg.detect_vuln(UnterminatedBuffer, func)
    nose.tools.ok_(result != None, "Could not find a UnterminatedBuffer opportunity")