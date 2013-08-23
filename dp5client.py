import dp5 
import sys
import json
import random

import requests

# Turn on when valid certificates are expected
# (off for debugging on localhost)
SSLVERIFY = False

class dp5client:
    def __init__(self, servers, private_key):
        self._regserver = servers["regServer"]
        self._lookupservers = servers["lookupServers"]
        self._priv = private_key

        # Access the network to retrive the configuration
        url = "https://" + self._regserver
        self._params = requests.get(url, verify=SSLVERIFY).json()

        # Make sure we are in sync    
        if int(self._params["epoch"] != dp5.getepoch()):
            msg = "Client and Server epoch out of sync. \
                  (Client: %s Server: %s)" % (dp5.getepoch(), self._params["epoch"]) 
            raise Exception(msg)

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
        reqs = dp5.clientlookuprequest(self._client, buddies)
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

if __name__ == "__main__":

    ### Example data
    pubk,privk = dp5.genkeypair()

    ## Make up some friends
    buddies = [(pubk, "*"*dp5.getdatasize())] # add myself as a friend
    for f in range(10):
        pub, _ = dp5.genkeypair()
        data = ("F%s" % f).center(dp5.getdatasize(), "-")
        buddies += [(pub,data)]   
        
    servers = json.load(file(sys.argv[1]))
            
    aclient = dp5client(servers, privk)
    aclient.register(buddies)

    ## Simulate an time period advance 
    url = "https://" + servers["regServer"] + "/debugfastforward"
    ff = requests.get(url, verify=SSLVERIFY)
    print ff.content

    buds = [b for b, _ in buddies]   
    presence = aclient.lookup(buds, dp5.getepoch() + 1)
    print "Presence:", presence 
    
