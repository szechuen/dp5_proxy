#!/usr/bin/python

import dp5
import cPickle          
import sys   
import random    

class User:
    def __init__(self, pub, priv, buddies):
        self.pub = pub
        self.priv = priv
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

    keys = [dp5.genkeypair() for _ in range(numusers)]

    pubs = [pub for pub,_ in keys]
    
    users = [User(pub,priv,random.sample(pubs, numfriends)) for pub,priv in keys] 
    
    cPickle.dump(users, output)
    
    
                 
