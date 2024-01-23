from dorat.schema import DoratVariable, DoratFunction
# These should probably be factored out into a separate
# function analysis module and be part of a Variable class or something
def isLocal(name, function : DoratFunction):
    return name in [v.name for v in function.variables]

def isParameter(name : str, function: DoratFunction):
    return name in function.arguments

def getLocal(name, function) -> DoratVariable:
    for v in function.variables:
        if v.name == name:
            return v