#!/usr/bin/env python3

import psutil, struct, time, os, sys
from subprocess import call
from multiprocessing import Pool
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.memory_mapping import readProcessMappings

def bytesToFloat(b):
    (f,) = struct.unpack('f', b)
    return f

def floatToBytes(f):
    return struct.pack('f', f)

def async_call():
    call(['sudo', '-i', '-u', sys.argv[1], os.getcwd() + '/hon-x86_64'])

hon_pid = 0

if len(sys.argv) != 2:
    print('you should start it as:\n ' + sys.argv[0] + ' <username>')
    sys.exit(-1)

isStarted = False

pool = Pool(processes=1)
result = pool.apply_async(async_call)

while not isStarted:
    for pid in psutil.pids():
        if psutil.Process(pid).name() == 'hon-x86_64':
            hon_pid = pid
            isStarted = True
            print('isStarted == True\npid={}'.format(hon_pid))
            break
    time.sleep(10.0)
    print('sleeping...')

print('starting debugger')
dbg = PtraceDebugger()
process = dbg.addProcess(hon_pid, False)
memory_mapping = readProcessMappings(process)

print('found memory mappings')
_next = False
for addr in memory_mapping:
    if _next == True:
        for a in range(addr.start, addr.end, 4):
            value = bytesToFloat(process.readBytes(a, 4))
            if value == 1850.:
                print("value is {} at addr {}".format(value, hex(a)))
                process.writeBytes(a, floatToBytes(2400.))
        break

    if 'rw' in addr.permissions and addr.pathname and 'libgame_shared' in addr.pathname:
        _next = True

