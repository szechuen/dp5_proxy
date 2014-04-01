from dp5asyncclient import *
# from dp5cffi import *
from dp5clib import *
from dp5cffi import *
InitLib()

import os
import sys
import json
import copy
import shutil

from users import User
import cPickle


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

    try:
        shutil.rmtree("fakereg")
    except Exception, e:
        # raise e
        pass

    try:
        shutil.rmtree("fakedata")
    except Exception, e:
        # raise e
        pass

    os.mkdir("fakereg")
    os.mkdir("fakedata")


    bls = BLSKeys()
    regconfig = DP5Config(config["standard"]["epochLength"], 16 + bls.pub_size(), False)
    epoch = regconfig.current_epoch() # + 1000
    server = RegServer(regconfig, "fakereg", "fakedata", epoch-1)

    def send_registration(cli, epoch, combined, msg, cb, fail):
        if combined:
            raise Exception("Should not trigger CB registration")
        else:
            print "Register ..."
            reply = server.register(msg)
            cb(reply)

    clients = []
    for x, u in enumerate(uxs):
        state = copy.deepcopy(config)
        state["Name"] = ("Client%07d" % x)
        state["ltID"] = u.dh
        state["bls"] = u.bls

        xcli = AsyncDP5Client(state)
        xcli.DEBUG_fake_epoch = xcli.epoch() - 1
        for i,f in enumerate(u.buddies):
            xcli.set_friend(f, "F%s"%i)

        xcli.register_handlers += [send_registration]
        xcli.set_event_handler(handler)
        clients += [xcli]

    for xcli in clients:
        xcli.register_ID()

    
    try:
        shutil.rmtree("fake")
    except Exception, e:
        # raise e
        pass

    os.mkdir("fake")



    server.epoch_change("fake/meta%d.dat" % (epoch), "fake/data%d.dat" % (epoch))
        
    try:
        shutil.rmtree("fakereg")
    except Exception, e:
        # raise e
        pass

    try:
        shutil.rmtree("fakedata")
    except Exception, e:
        # raise e
        pass
