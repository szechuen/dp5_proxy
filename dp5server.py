import cherrypy
import json
import sys
import traceback

import dp5


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

        self.is_register = config["isRegServer"]
        self.register_handlers = {}

        self.is_lookup = config["isLookupServer"]
        self.lookup_handlers = {}

        # For debugging
        self._add = 0

        self.check_epoch()


    def filenames(self, epoch):
        return ("%s/meta%d.dat" % (self.config["datadir"], epoch), "%s/data%d.dat" % (self.config["datadir"], epoch))

    def getepoch(self, add=0):
        self._add += add
        return dp5.getepoch() + self._add

    def update_lookup(self):
        if self.is_lookup:
            assert self.epoch not in self.lookup_handlers
            ## TODO: If local files are not available
            ##        Retrieve them from the registration
            ##        server using HTTPs.
            try:
                metafile, datafile = self.filenames(self.epoch)

                ## Throw exception if not found
                open(metafile)
                open(datafile)

                server = dp5.getnewserver()

                dp5.serverinitlookup(server, self.epoch, metafile, datafile)
                self.lookup_handlers[self.epoch] = server
            except:
                print "No metadatafile available"
                pass

            ## TODO: Delete old instances of the server


    def check_epoch(self):
        if self.epoch == None:

            ## Initialize for this epoch
            self.epoch = dp5.getepoch()

            if self.is_register:
                ## Initialize a new registration server
                server = dp5.getnewserver()
                dp5.serverinitreg(server, self.epoch, self.config["regdir"], self.config["datadir"])
                self.register_handlers[self.epoch] = server

            self.update_lookup()

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

            self.update_lookup()

        else:
            pass # do nothing

    @cherrypy.expose
    def index(self, **keywords):
        "Returns the server parameters, incl. routing parameters."
        self.check_epoch()
        params = {}
        params["epoch"] = self.epoch
        params["register"] = (self.epoch in self.register_handlers)

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
        ## First check if we are a registration server in a valid state
        try:
            self.check_epoch()
            assert self.epoch == int(epoch)
            assert self.is_register
            assert self.epoch in self.register_handlers
        except:
            raise cherrypy.HTTPError(403)

        ## Now register the client
        ## TODO: do the simplest of authentications
        server = self.register_handlers[self.epoch]

        post_body = cherrypy.request.body.read()
        reply_msg = dp5.serverclientreg(server, post_body)

        ## Reply with the raw data
        cherrypy.response.headers["Content-Type"] = "application/octet-stream"
        return reply_msg

    @cherrypy.expose
    def lookup(self, epoch):
        try:
            self.check_epoch()
            assert self.epoch == int(epoch)
            assert self.is_lookup
            assert self.epoch in self.lookup_handlers
        except:
            raise cherrypy.HTTPError(403)

        server = self.lookup_handlers[self.epoch]

        post_body = cherrypy.request.body.read()
        reply_msg = dp5.serverprocessrequest(server, post_body)

        ## Reply with the raw data
        cherrypy.response.headers["Content-Type"] = "application/octet-stream"
        return reply_msg

    @cherrypy.expose
    def download(self, epoch, metadata=False):
        try:
            metaname, dataname = self.filenames(int(epoch))
            if metadata:
                f = open(metaname)
            else:
                f = open(dataname)
            cherrypy.response.headers["Content-Type"] = "application/octet-stream"
            return f.read()
        except:
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
