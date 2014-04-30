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

import limits
limits.set_limits()

cherrypy.config.update({'environment': 'embedded'})

if cherrypy.__version__.startswith('3.0') and cherrypy.engine.state == 0:
    cherrypy.engine.start(blocking=False)
    atexit.register(cherrypy.engine.stop)

config = json.load(file(sys.argv[1]))
print "Using config file:", sys.argv[1]
cherrypy.config.update(dict(map(fromUnicode,x) for x in config["server"].items()))

cherrypy.config.update({
    'log.access_file': "logs/log-{0}-cherrypy-access.log".format(sys.argv[1]),
    'log.error_file': "logs/log-{0}-cherrypy-error.log".format(sys.argv[1])
})

cherrypy.config.update( {'log.screen': False})


application = cherrypy.Application(RootServer(config), script_name=None, config=None)

reactor.suggestThreadPoolSize(10)
TP = reactor.getThreadPool()
resource = WSGIResource(reactor, TP, application)
reactor.listenSSL(config["server"]["server.socket_port"], Site(resource), ssl.DefaultOpenSSLContextFactory(
            'testcerts/server.key', 'testcerts/server.crt'))

if __name__ == "__main__":
    reactor.run()
