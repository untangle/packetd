import os
import sys
import subprocess

__moduleDict = {}

def registerModule(moduleName, clz):
    global __moduleDict
    __moduleDict[moduleName] = clz

def allModules():
    global __moduleDict
    moduleList = sorted(__moduleDict.keys())
    return moduleList

def allTests():
    global __moduleDict
    return __moduleDict.values()

def getTest(moduleName):
    global __moduleDict
    try:
        return __moduleDict[moduleName]
    except Exception as e:
        return None
