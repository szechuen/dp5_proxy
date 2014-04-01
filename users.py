#!/usr/bin/python

from dp5clib import *
from dp5cffi import *

InitLib()

import cPickle          
import sys   
import random    

class User:
    def __init__(self, keys, buddies):
        dh, bls = keys
        self.dh = dh.tobuffer()
        self.bls = bls.tobuffer()
        self.buddies = buddies

if __name__ == "__main__":
    try:
        numusers = int(sys.argv[1])
        output = file(sys.argv[2], 'w')
    except:                           
        print "Usage: %s numusers picklefile" % sys.argv[0]
        sys.exit(1)

    # FIXME: parametrize?
    numfriends = min(50, numusers)

    keys = [(DHKeys(), BLSKeys()) for _ in range(numusers)]
    for k1,k2 in keys:
        k1.gen()
        k2.gen()

    pubs = [dh.pub() for dh,_ in keys]
    
    users = [User(K,random.sample(pubs, numfriends)) for K in keys] 
    
    cPickle.dump(users, output)
    
    
                 
