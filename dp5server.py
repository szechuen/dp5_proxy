import cherrypy
import json
import sys
import traceback
import requests
import threading

import dp5
import os
import fcntl
from dp5logs import logger


SSLVERIFY = False

# How to generate an RSA self-signed cert using openssl
#
# openssl genrsa -des3 -out server.key 1024
# openssl req -new -key server.key -out server.csr
# cp server.key server.key.org
# openssl rsa -in server.key.org -out server.key
# openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

class RootServer:

    def __init__(self, config):
        self.epoch = None

        self.config = config

        self.dp5config = dp5.make_config(config["epochLength"],
            config["dataEncSize"], config["combined"])

        self.is_register = config["isRegServer"]
        self.register_handlers = {}

        self.is_lookup = config["isLookupServer"]
        self.lookup_handlers = {}

	# Make sure directories exist
        if not os.path.exists(config["datadir"]):
            os.makedirs(config["datadir"])

	if config.has_key("regdir") and not os.path.exists(config["regdir"]):
            os.makedirs(config["regdir"])
        if not os.path.exists("logs/"):
            os.makedirs("logs/")

        # For debugging
        self._add = 0

        self.lookup_lock = threading.Lock()

        self.check_epoch()
        name = "LOOKUP" if config["isLookupServer"] else "REG"
        name += "CB" if config["combined"] else "NORM"

        self.log = logger(name, name)
        self.aid = 0
        print "Load logger"


    def filenames(self, epoch):
        return ("%s/meta%d.dat" % (self.config["datadir"], epoch), "%s/data%d.dat" % (self.config["datadir"], epoch))

    def getepoch(self, add=0):
        self._add += add
        return dp5.getepoch(self.dp5config) + self._add

    def lookup_server(self, epoch, asaid):
        if not self.is_lookup:
            return None
        if epoch in self.lookup_handlers:       # We're assuming element assignment and lookup is atomic so we can do this check without
            return self.lookup_handlers[epoch]  # acquiring the lock
        with self.lookup_lock:
            if epoch in self.lookup_handlers:   # Redo the check to avoid race conditions
                return self.lookup_handlers[epoch]

            metafile, datafile = self.filenames(epoch)

            for filename in [metafile, datafile]:
                # All locks will be released when file closed
                # as this with block is exited
                with open(filename + ".lock", "w") as lockf:
                    fcntl.flock(lockf, fcntl.LOCK_SH)
                    try:
                        with open(filename):    # File exists, we're good
                            continue
                    except:
                        pass                    # File doesn't exist, continue

                    # Remove read lock to prevent deadlock
                    # and then acquire exclusive lock
                    fcntl.flock(lockf, fcntl.LOCK_UN)
                    fcntl.flock(lockf, fcntl.LOCK_EX)

                    # Check again if file exists
                    try:
                        with open(filename):    # File exists, we're good
                            continue
                    except:
                        pass                    # File doesn't exist, continue

                    cherrypy.log("Downloading " + filename)
                    self.log.log(("LOOK","DOWNLOAD", "START"), asaid)
                    r = requests.get(self.config["regServer"] + "/download/%d%s" % (epoch, filename == metafile and "/meta" or ""), verify=SSLVERIFY)
                    r.raise_for_status()        # Throw exception if download failed
                    
                    self.log.log(("LOOK","DOWNLOAD", "SIZE", str(len(r.content))), asaid)
                    with file(filename, 'w') as f:
                        f.write(r.content)

                    self.log.log(("LOOK","DOWNLOAD", "SUCCESS"), asaid)

            server = dp5.getnewserver(self.dp5config)

            dp5.serverinitlookup(server, epoch, metafile, datafile)
            assert epoch not in self.lookup_handlers
            self.lookup_handlers[epoch] = server
            return server

    def check_epoch(self):
        if self.epoch == None:

            ## Initialize for this epoch
            self.epoch = dp5.getepoch(self.dp5config)

            if self.is_register:
                ## Initialize a new registration server
                server = dp5.getnewserver(self.dp5config)
                dp5.serverinitreg(server, self.epoch, self.config["regdir"], self.config["datadir"])
                self.register_handlers[self.epoch] = server

        elif self.epoch < self.getepoch():

            ## Move epoch and initialize
            if self.is_register:
                assert self.epoch in self.register_handlers
                server = self.register_handlers[self.epoch]

                ## Save DB and update epoch
                meta_name, data_name = self.filenames(self.epoch+1)
                self.epoch = dp5.serverepochchange(server, meta_name, data_name)
                self.register_handlers[self.epoch] = server
            else:
                self.epoch = self.getepoch()

        else:
            pass # do nothing

    @cherrypy.expose
    def index(self, **keywords):
        "Returns the server parameters, incl. routing parameters."
        self.check_epoch()
        params = {}
        params["epoch"] = self.epoch
        params["register"] = (self.epoch in self.register_handlers)
        self.log.log(("SERVE EPOCH",), 0)
        return json.dumps(params)

    @cherrypy.expose
    def debugfastforward(self):
        old = self.getepoch()
        self.getepoch(add=1)
        self.check_epoch()
        new = self.getepoch()
        return "Old: %s New: %s" % (old, new)


    @cherrypy.expose
    def register(self, epoch):
        "Register a number of friends"

        myaID = self.aid 
        self.aid += 1
        self.log.log(("REG", "START", str(int(epoch))), myaID)

        # print "Register request for epoch %s" % epoch
        ## First check if we are a registration server in a valid state        
        try:
            self.check_epoch()
            #print self.epoch, epoch
            assert self.epoch == int(epoch)
            assert self.is_register
            assert self.epoch in self.register_handlers
            assert cherrypy.request.process_request_body
        except:
            print "Epoch", self.epoch == int(epoch), (self.epoch, int(epoch))
            print "Register", self.is_register
            print "Handlers", self.epoch in self.register_handlers
            print "POST", cherrypy.request.process_request_body
            print "Register request (epoch = %s) fail." % epoch
            self.log.log(("REG", "FAIL", str(self.epoch)), myaID)

            raise cherrypy.HTTPError(403)

        try:
            ## Now register the client
            ## TODO: do the simplest of authentications
            server = self.register_handlers[self.epoch]

            post_body = cherrypy.request.body.read()
            self.log.log(("REG", "INSIZE", str(len(post_body))), myaID)

            reply_msg = dp5.serverclientreg(server, post_body)

            self.log.log(("REG", "OUTSIZE", str(len(reply_msg))), myaID)

            ## Reply with the raw data
            cherrypy.response.headers["Content-Type"] = "application/octet-stream"
            # print "Register request (epoch = %s) done." % epoch
            self.log.log(("REG", "SUCCESS",), myaID)

            return reply_msg
        except Exception as e:
            # print "Register request (epoch = %s) fail." % epoch
            traceback.print_exc()
            self.log.log(("REG", "FAIL", str(e)), myaID)
            raise e


    @cherrypy.expose
    def lookup(self, epoch):
        assert self.is_lookup
        assert cherrypy.request.process_request_body
        # print "Lookup request for epoch %s" % epoch

        # Lazily set up lookup server
        myaID = self.aid 
        self.aid += 1
        self.log.log(("LOOK","START"), myaID)

        server = self.lookup_server(int(epoch), asaid = myaID)

        post_body = cherrypy.request.body.read()
        self.log.log(("LOOK","INSIZE", str(len(post_body))), myaID)

        reply_msg = dp5.serverprocessrequest(server, post_body)
        self.log.log(("LOOK","OUTSIZE", str(len(reply_msg))), myaID)

        ## Reply with the raw data
        cherrypy.response.headers["Content-Type"] = "application/octet-stream"
        # print "Return length", len(reply_msg)
        self.log.log(("LOOK","SUCCESS"), myaID)

        return reply_msg

    @cherrypy.expose
    def download(self, epoch, metadata=False):
        myaID = self.aid 
        self.aid += 1
        self.log.log(("DOWNLOAD","START"), myaID)
        try:
            with self.lookup_lock:
                self.check_epoch()
                metaname, dataname = self.filenames(int(epoch))
                if metadata:
                    f = open(metaname)
                else:
                    f = open(dataname)
                cherrypy.response.headers["Content-Type"] = "application/octet-stream"
                self.log.log(("DOWNLOAD","SUCESS"), myaID)
                return f.read()
        except:
            self.log.log(("DOWNLOAD","FAIL"), myaID)
            raise cherrypy.HTTPError(403)

def fromUnicode(x):
    if type(x) == unicode:
        return str(x)
    else:
        return x

if __name__ == '__main__':
    config = json.load(file(sys.argv[1]))
    cherrypy.config.update(dict(map(fromUnicode,x) for x in config["server"].items()))
    cherrypy.quickstart(RootServer(config))
