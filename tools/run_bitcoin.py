#!/usr/bin/env python2.7

import os, sys, subprocess, shutil, argparse
import subprocess
from datetime import datetime

DEFAULTOUTPUT=os.path.abspath(os.path.expanduser("./"))
    
def reset(output, count, template):
    if os.path.exists(output+"/data"): shutil.rmtree(output+"/data")
    os.mkdir(output+"/data")
    os.symlink(output+"/initdata/pristine", output+"/data/pristine")
    print 'template', template
    for i in range(1,count+1):
        print >> sys.stderr, "copying " + output+"/data/.bitcoin%d" % i
        if template is not None:
            shutil.copytree(template, output+"/data/.bitcoin%d" % i, symlinks=True)
        else:
            os.mkdir(output+"/data/.bitcoin%d" % i)

if __name__ == '__main__':
    output = DEFAULTOUTPUT
    datapath = os.path.abspath(output+"/data")
    if len(sys.argv) < 3:
        print 'usage: run_bitcoin.py <template_dir> <N>'
        sys.exit(1)

    template = sys.argv[1]
    n = int(sys.argv[2])
    reset(output, n, template)

    ps = []
    import random
    edges = set()
    for i in range(1,n+1):
        datadir = output+"/data/.bitcoin%d" % i
        port = 8332+i
        conns = [random.randint(1,n) for _ in range(2)]
        conns = filter(lambda x: x != i, conns)
        for c in conns:
            edges.add(tuple(sorted((i,c))))
        conns = ' '.join('-connect=localhost:%d'%(8332+j) for j in conns)
        #  -connect=localhost:8433
        cmd = './bitcoin/src/bitcoind -checkblocks=1 -checklevel=1 -server=0 -listen -debug -port={port} -datadir={datadir} -umd_loadindexsnapshot=./snapshot_300k.dat -par=1 {conns} -externalip=100.100.100.100'
        cmd = cmd.format(datadir=datadir,port=port,ip=i,conns=conns)
        ps.append(subprocess.Popen(cmd, shell=True, close_fds=True))

    for i,j in sorted(edges):
        print i, '<->', j

    import signal
    def kill_child():
        for p in ps: p.kill()

    import atexit
    atexit.register(kill_child)

    for p in ps: p.wait()
