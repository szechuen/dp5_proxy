from dp5asyncclient import *
# from dp5cffi import *
from dp5clib import *
from dp5cffi import *
InitLib()

from pprint import pformat

from twisted.internet import reactor
from twisted.internet import task
from twisted.internet.defer import Deferred
from twisted.internet.protocol import Protocol, connectionDone
from twisted.web.client import Agent, ResponseDone, HTTPConnectionPool
from twisted.web.http_headers import Headers
from twisted.web.client import FileBodyProducer

from twisted.internet.defer import setDebugging
setDebugging(True)

from StringIO import StringIO
import traceback
import sys
import json
import copy

from users import User
import cPickle

SSLPOOL = True

## Common pool of HTTPs connection to
## ensure that SSL is not the bottle neck.
if SSLPOOL:
    commonhttppool = HTTPConnectionPool(reactor, persistent=True)
    commonhttppool.maxPersistentPerHost = 5
    commonhttppool.retryAutomatically = False
else:
    commonhttppool = None


class BufferedReception(Protocol):
    def __init__(self, finished):
        self.finished = finished
        self.bytes = None

    def dataReceived(self, bytes):        
        if self.bytes == None:
            self.bytes = StringIO()
        self.bytes.write(bytes)

    def connectionLost(self, reason):
        if reason.type == ResponseDone and self.bytes != None:
            data = self.bytes.getvalue()
            self.finished.callback(data)
        else:
            self.finished.errback(reason)

def dp5twistedclientFactory(state):
    global commonhttppool
    ## Build an async client
    cli = AsyncDP5Client(state)
    
    # Use a common pool of HTTPs connections
    if commonhttppool is None:
        httppool = HTTPConnectionPool(reactor, persistent=True)
        httppool.maxPersistentPerHost = 5
        httppool.retryAutomatically = False
    else:
        httppool = commonhttppool

    cli.pool = httppool
    cli.agent = Agent(reactor, pool=httppool)
    cli.inflight = 0

    ## Define the networking for registration
    def send_registration(cli, epoch, combined, msg, cb, xfail):
        if combined:
            ser = cli.state["combined"]["regServer"]
            surl = str("https://"+ser+"/register?epoch=%s" % (epoch-1))
        else:
            ser = cli.state["standard"]["regServer"]
            surl = str("https://" + ser + "/register?epoch=%s" % (epoch-1))

        cli.inflight += 1
        try:
            body = FileBodyProducer(StringIO(msg))

            d = cli.agent.request(
                'POST',
                surl,
                Headers({'User-Agent': ['DP5 Twisted Client']}),
                body)

            def err(*args):
                # print "REG ERROR", args
                # print args
                cli.inflight -= 1
                xfail(args[0])

            def cbRequest(response):
                finished = Deferred()
                finished.addCallback(cb)
                finished.addErrback(err)
                response.deliverBody(BufferedReception(finished))
                cli.inflight -= 1
                return finished

            d.addCallback(cbRequest)
            d.addErrback(err)
        except Exception as e:
            print e
            cli.inflight -= 1
            err(e)

    cli.register_handlers += [send_registration]

    ## Define the networking for lookups
    def send_lookup(cli, epoch, combined, seq, msg, cb, xfail):
        if msg == "":
            #print "No need to relay lookup"
            return cb("")

        if combined:
            ser = cli.state["combined"]["lookupServers"][seq]
            surl = str("https://"+ser+"/lookup?epoch=%s" % epoch)
        else:
            ser = cli.state["standard"]["lookupServers"][seq]
            surl = str("https://" + ser + "/lookup?epoch=%s" % epoch)

        cli.inflight += 1
        try:
            body = FileBodyProducer(StringIO(msg))

            d = cli.agent.request(
                'POST',
                surl,
                Headers({'User-Agent': ['DP5 Twisted Client']}),
                body)

            def err(*args):
                cli.inflight -= 1
                xfail(args[0])

            def cbRequest(response):
                finished = Deferred()
                finished.addCallback(cb)
                finished.addErrback(err)
                response.deliverBody(BufferedReception(finished))
                cli.inflight -= 1
                return finished
            
            d.addCallback(cbRequest)
            d.addErrback(err)
        except Exception as e:
            print e
            cli.inflight -= 1
            err(e)



    cli.lookup_handlers += [send_lookup]

    def loopupdate():
        cli.update()

    cli.l = task.LoopingCall(loopupdate)
    period = float(cli.state["epoch_lengthCB"] / 4.0)
    print "Update every %2.2f secs" % period
    cli.l.start(period) # call every second
    return cli

if __name__ == "__main__":
    try:
        config = json.load(file(sys.argv[1]))
        print "Loading config from file \"%s\"" % sys.argv[1]
    except Exception as e:
        traceback.print_exc()
        config = {}
        print "No configuration file"
        sys.exit(1)

    ## Now load a standard file of users
    try:
        uxs = cPickle.load(file(sys.argv[2]))
    except Exception as e:
        print "No users file specified"
        print e
        sys.exit(1)

    ## ------------------------------------ ##
    ## --- Overwrite this modest function - ##
    ## --- for the client to do something - ##
    ## ------------------------------------ ##
    def handler(state, event, hid):              ##
            pass
            # print state["Name"], event      ##
    ## ------------------------------------ ##
    ## ------------------------------------ ##
    ## ------------------------------------ ##

    clients = []
    for x, u in enumerate(uxs):
        state = copy.deepcopy(config)
        state["Name"] = ("Client%07d" % x)
        state["ltID"] = u.dh
        state["bls"] = u.bls

        xcli = dp5twistedclientFactory(state)
        for i,f in enumerate(u.buddies):
            xcli.set_friend(f, "F%s"%i)

        xcli.set_event_handler(handler)
        clients += [xcli]

    reactor.run()
