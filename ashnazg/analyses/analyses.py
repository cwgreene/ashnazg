# for forward references
from __future__ import annotations

import smrop
import logging
import json
import claripy

import pwn

logger = logging.getLogger(name=__name__)

ANALYSES_TOP = []
def register(clazz):
    # TODO: probably don't want to instantiate
    # here, makes more sense to instantiate
    # when the program context is available.
    ANALYSES_TOP.append(clazz)
    return clazz

ANALYSES_PARTIAL = []
def partial(clazz):
    ANALYSES_PARTIAL.append(clazz)
    return clazz

def toplevel():
    return ANALYSES_TOP

def partials():
    return ANALYSES_PARTIAL

class Vulnerability:

    @staticmethod
    def detect(context, function, program):
        raise NotImplementedError()
    
    @staticmethod
    def detect_all(context, function, program):
        raise NotImplementedError()
    
    # Probably don't care about this interface, we instantiate in detect
    def __init__(self, function, binary : pwn.ELF, libc : pwn.ELF):
        raise NotImplementedError()
    
    def exploit(self, function):
        raise NotImplementedError()
    
    def export(self):
        raise NotImplementedError()
    
    def dpause(self, conn : Connection):
        if conn.debug:
            print(conn.conn.pid)
            pwn.pause()
