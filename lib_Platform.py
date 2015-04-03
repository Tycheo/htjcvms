import platform

def get3264():
    return platform.uname()[4]

def getos():
    return platform.uname()[0]

def islinux():
    if getos()=='Linux':
        return True
    return False

def iswindows():
    if getos()=='Windows':
        return True
    return False

def getlinuxdist():
    if islinux:
        return platform.dist()
    
def getpythonv():
    return platform.python_version()

def requiredPV(pv):
    if pv==getpythonv()[:2]:
        return True
    