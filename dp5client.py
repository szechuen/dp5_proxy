import dp5 
import sys
import json
import random 
import cPickle
from users import User
import math
from binascii import hexlify     
import multiprocessing

import requests

# Turn on when valid certificates are expected
# (off for debugging on localhost)
SSLVERIFY = False

class dp5client:
    def __init__(self, config, private_key):
        self._regserver = config["regServer"]
        self._lookupservers = config["lookupServers"]
        try: 
            self._privacyLevel = config["privacyLevel"]
        except: 
            self._privacyLevel = len(self._lookupservers)-1
        self._priv = private_key

        # Access the network to retrive the configuration
        url = "https://" + self._regserver
        self._params = requests.get(url, verify=SSLVERIFY).json()

        # Make sure we are in sync    
        if int(self._params["epoch"] != dp5.getepoch()):
            msg = "Client and Server epoch out of sync. \
                  (Client: %s Server: %s)" % (dp5.getepoch(), self._params["epoch"]) 
            #raise Exception(msg)
            print msg

        # Initialize the client
        self._client = dp5.getnewclient(self._priv)

    def register(self,buddies):
        # Create the registration request
        next_epoch = dp5.getepoch() + 1
        reg_msg = dp5.clientregstart(self._client, next_epoch, buddies);

        # Perform the request
        epoch = dp5.getepoch()
        url = "https://" + self._regserver + ("/register/%s/" % epoch)
        reply = requests.post(url, verify=SSLVERIFY, data=reg_msg)

        # Finish the request
        dp5.clientregcomplete(self._client, reply.content, next_epoch)

    def lookup(self, buddies, epoch=None):
        metamsg = dp5.clientmetadatarequest(self._client, epoch)  
        
        url = "https://" + random.choice(self._lookupservers) + ("/lookup/%s/" % epoch)
        metareply = requests.post(url, verify=SSLVERIFY, data=metamsg)        
        dp5.clientmetadatareply(self._client, metareply.content)

        ## TODO: Use a few threads to paralelize
        reqs = dp5.clientlookuprequest(self._client, buddies, len(self._lookupservers), self._privacyLevel)
        replies = []
        for r in reqs:
            if r != None:                             
                server = self._lookupservers[len(replies) % len(self._lookupservers)]
                ## TODO: Read addresses of other servers in DP5 cluster
                url = "https://" + server + ("/lookup/%s/" % epoch)
                lookupreply = requests.post(url, verify=SSLVERIFY, data=r)        
                replies += [lookupreply.content]
            else:
                replies += [None]
        presence = dp5.clientlookupreply(self._client, replies)
        return presence
            
prefix = 3

import os
def regfun(u):
    print "Register", hexlify(u.pub[:prefix])
    buddies = [(pub, ('%s->%s' % (hexlify(u.pub[:prefix]),hexlify(pub[:prefix]))).center(dp5.getdatasize())) for pub in u.buddies]
    u.client = dp5client(servers, u.priv)
    u.client.register(buddies)

def lookupfun(u):
    presence = dp5client(servers,u.priv).lookup(u.buddies, dp5.getepoch()+1)  
    print "Presence:", hexlify(u.pub[:prefix]), presence


if __name__ == "__main__":  
                                                         
    try:
        servers = json.load(file(sys.argv[1]))
        users = cPickle.load(file(sys.argv[2]))
    except:
        print "Usage:", sys.argv[0], "servers.cfg", "userfile" 
        sys.exit(1)
                                                               
    # 5x number of cores to 
    pool = multiprocessing.Pool(multiprocessing.cpu_count() * 5)
        
    results = [pool.apply_async(regfun, args=(u,)) for u in users]

    # Wait for all results
    for r in results:
        r.get()
                          
    ## Simulate an time period advance 
    url = "https://" + servers["regServer"] + "/debugfastforward"
    ff = requests.get(url, verify=SSLVERIFY)
    print ff.content   
        
    results = [pool.apply_async(lookupfun, args=(u,)) for u in users]

    # Wait for all results
    for r in results:
        r.get()    
