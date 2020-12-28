ANALYSES = []
def register(clazz):
    c = clazz()
    ANALYSES.append(c)

class Vulnerability:
    def detect(self, function, program):
        raise NotImplementedError()
    
    def exploit(self, function):
        raise NotImplementedError()

@register
class GetsVulnerability(Vulnerability):
    def detect(self, function, program):
        for call in function["calls"]:
            if call["funcName"] == "gets":
                return True
        return False

    def exploit(self, function, program):
        getscall = None
        for call in function["calls"]:
            if call["funcName"] == "gets":
                getscall = call
            break
        # assume stack for now
        # need to add check to validate
        # that the argument is on the stack.
        # otherwise, this is not exploitable
        # via this technique
        arg = getscall["arguments"][0]
        offset = arg["stackOffset"]
        payload = ""
