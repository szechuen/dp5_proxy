import dp5
import sys
import json
import random
import cPickle
from users import User
import math
from binascii import hexlify
import multiprocessing
import time

import requests

# Turn on when valid certificates are expected
# (off for debugging on localhost)
SSLVERIFY = False
protocol = "https"



class dp5client:
    def __init__(self, config, private_key):
        self.protocol = protocol ## FIX global variable
        self._regserver = config["regServer"]
        self._lookupservers = config["lookupServers"]
        self._numlookupservers = len(self._lookupservers)
        try:
            self._privacyLevel = config["privacyLevel"]
        except KeyError:
            self._privacyLevel = len(self._lookupservers)-1
        self._priv = private_key
        self._config = dp5.make_config(config["epochLength"],
            config["dataEncSize"], False)

        # Access the network to retrive the configuration
        url = self.protocol +"://" + self._regserver
        self._params = requests.get(url, verify=SSLVERIFY).json()

        # Make sure we are in sync
        if int(self._params["epoch"] != dp5.getepoch(self._config)):
            msg = "Client and Server epoch out of sync. \
                  (Client: %s Server: %s)" % (dp5.getepoch(self._config), self._params["epoch"])
            #raise Exception(msg)
            #print msg

        # Initialize the client
        self._client = dp5.getnewclient(self._config, self._priv)



    def register(self,buddies):
        # Create the registration request
        next_epoch = dp5.getepoch(self._config) + 1
        reg_msg = dp5.clientregstart(self._client, next_epoch, buddies);

        # Perform the request
        epoch = dp5.getepoch(self._config)
        url = self.protocol + "://" + self._regserver + ("/register/%s/" % epoch)
        reply = requests.post(url, verify=SSLVERIFY, data=reg_msg)

        # Finish the request
        dp5.clientregcomplete(self._client, reply.content, next_epoch)

    def lookup(self, buddies, epoch=None):
        metamsg = dp5.clientmetadatarequest(self._client, epoch)

        url = self.protocol + "://" + random.choice(self._lookupservers) + ("/lookup/%s/" % epoch)
        metareply = requests.post(url, verify=SSLVERIFY, data=metamsg)
        dp5.clientmetadatareply(self._client, metareply.content)

        reqs = dp5.clientlookuprequest(self._client, buddies, len(self._lookupservers), self._privacyLevel)
        replies = []
        pool = multiprocessing.pool.ThreadPool(processes=self._numlookupservers)
        for req,server in zip(reqs,self._lookupservers):
            if req != None:
                url = self.protocol + "://" + server + ("/lookup/%s/" % epoch)
                replies.append(pool.apply_async(requests.post, args=(url,), kwds={'verify':SSLVERIFY, 'data':req}))
            else:
                replies.append(None)
        # Wait for replies to be received
        realreplies = []
        for r in replies:
            if r:
                realreplies.append(r.get().content)
            else:
                realreplies.append(None)
        presence = dp5.clientlookupreply(self._client, realreplies)
        return presence

prefix = 3

import os
def regfun(u):
    #print "Register", hexlify(u.pub[:prefix])
    # FIXME: should the "16" here be configurable?
    buddies = [(pub, ('%s->%s' % (hexlify(u.pub[:prefix]),
        hexlify(pub[:prefix]))).center(servers["dataEncSize"]-16)) for pub in u.buddies]
    u.client = dp5client(servers, u.priv)
    u.client.register(buddies)

def lookupfun(u):
    client = dp5client(servers,u.priv)

    presence = client.lookup(u.buddies, dp5.getepoch(client._config)+1)
    #print "Presence:", hexlify(u.pub[:prefix]), presence


if __name__ == "__main__":

    try:
        servers = json.load(file(sys.argv[1]))
        users = cPickle.load(file(sys.argv[2]))
    except:
        print "Usage:", sys.argv[0], "servers.cfg", "userfile", "[lookups]"
        sys.exit(1)

    try:
        numlookups = int(sys.argv[3])
    except:
        numlookups = len(users)

    # 5x number of cores to
    pool = multiprocessing.Pool(multiprocessing.cpu_count() * 5)

    print "Registering..."
    start = time.time()
#    results = [pool.apply_async(regfun, args=(u,)) for u in users]

    # Wait for all results
#    for r in results:
#        r.get()
    for u in users:
        regfun(u)
    end = time.time()
    print "Done ({:.2f}s / {:.2f}ms / user)".format(end-start, (end-start)/len(users)*1000)

    ## Simulate an time period advance
    url = protocol + "://" + servers["regServer"] + "/debugfastforward"
    ff = requests.get(url, verify=SSLVERIFY)
    print ff.content

    print "Looking up"
    start = time.time()
    for u in random.sample(users, numlookups):
        lookupfun(u)
#    results = [pool.apply_async(lookupfun, args=(u,)) for u in random.sample(users, numlookups)]

    # Wait for all results
#    for r in results:
#        r.get()
    end = time.time()
    print "Done ({:.2f}s / {:.2f}ms / user)".format(end-start, (end-start)/numlookups*1000)
