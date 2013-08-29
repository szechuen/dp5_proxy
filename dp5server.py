import cherrypy
import json
import sys
import traceback
import requests
import threading

import dp5      
import os
import fcntl



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

        self.is_register = config["isRegServer"]
        self.register_handlers = {}

        self.is_lookup = config["isLookupServer"]
        self.lookup_handlers = {}

        # For debugging
        self._add = 0      
        
        self.lookup_lock = threading.Lock()

        self.check_epoch()


    def filenames(self, epoch):
        return ("%s/meta%d.dat" % (self.config["datadir"], epoch), "%s/data%d.dat" % (self.config["datadir"], epoch))

    def getepoch(self, add=0):
        self._add += add
        return dp5.getepoch() + self._add

    def lookup_server(self, epoch):
        if not self.is_lookup:
            return None 
        if epoch in self.lookup_handlers:       # We're assuming element assignment and lookup is atomic so we can do this check without 
            return self.lookup_handlers[epoch]  # acquiring the lock            
        self.lookup_lock.acquire()
        try:
            if epoch in self.lookup_handlers:   # Redo the check to avoid race conditions
                return self.lookup_handlers[epoch]
                        
            metafile, datafile = self.filenames(epoch)
                                      
            # FIXME: this is only needed if we have multiple server processes on the same file system
            for filename in [metafile, datafile]: 
                while True:  
                    try:
                        with open(filename) as f: 
                                while True:
                                    fcntl.flock(f, fcntl.LOCK_SH)
                                    f.seek(0, 2)      
                                    if f.tell() > 0:        # Download has been completed
                                        break
                                    else:          
                                        print "File not ready", filename
                                        fcntl.flock(f, fcntl.LOCK_UN) # Unlock for the other process
                                        time.sleep(1)       # FIXME: is this needed?
                                break   
                    except IOError:
                        print "No file", filename
                        if self.is_register:
                            return None
                        try:                  
                            fd = os.open(filename, os.O_CREAT | os.O_WRONLY | os.O_EXCL)
                        except:                  
                            print "Could not create file", filename
                            continue    # Could not create file, must already be being downloaded 
                        try:  
                            f = os.fdopen(fd, 'w')
                            fcntl.flock(f, fcntl.LOCK_EX)  # lock for exclusive access
                            r = requests.get(self.config["regServer"] + "/download/%d%s" % (epoch, filename == metafile and "/meta" or ""), verify=SSLVERIFY)
                            r.raise_for_status()
                            f.write(r.content)
                        except:            
                            print "Download failed"
                            os.remove(filename)     # Download failed, remove file
                            raise
                        finally:
                            f.close()       # close file and release lock

            server = dp5.getnewserver()

            dp5.serverinitlookup(server, epoch, metafile, datafile)
            self.lookup_handlers[epoch] = server
            return server
        finally:
            self.lookup_lock.release()

    def check_epoch(self):
        if self.epoch == None:

            ## Initialize for this epoch
            self.epoch = dp5.getepoch()

            if self.is_register:
                ## Initialize a new registration server
                server = dp5.getnewserver()
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
        assert self.is_lookup

    # Lazily set up lookup server 
        server = self.lookup_server(int(epoch))

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
