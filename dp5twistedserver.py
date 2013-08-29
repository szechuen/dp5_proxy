import sys
sys.stdout = sys.stderr

import atexit
import threading
import cherrypy
import json

from dp5server import RootServer, fromUnicode

from twisted.web.wsgi import WSGIResource
from twisted.web.server import Site
from twisted.internet import ssl, reactor

cherrypy.config.update({'environment': 'embedded'})

if cherrypy.__version__.startswith('3.0') and cherrypy.engine.state == 0:
    cherrypy.engine.start(blocking=False)
    atexit.register(cherrypy.engine.stop)

config = json.load(file(sys.argv[1]))
cherrypy.config.update(dict(map(fromUnicode,x) for x in config["server"].items()))
application = cherrypy.Application(RootServer(config), script_name=None, config=None)


resource = WSGIResource(reactor, reactor.getThreadPool(), application)
reactor.listenSSL(8443, Site(resource),ssl.DefaultOpenSSLContextFactory(
            'testcerts/server.key', 'testcerts/server.crt'))

if __name__ == "__main__":
    reactor.run()
