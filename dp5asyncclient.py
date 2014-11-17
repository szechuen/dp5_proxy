## ---- Async client

from dp5clib import *
from dp5logs import logger

import random
import traceback

class AsyncDP5Client:

    def __init__(self, state = None, numservers=3):
        InitLib()

        self.state = state
        if state == None:

            self.state = {}

        self.init_ID(data=self.state.get("ltID", None))
        self.init_BLS(data=self.state.get("bls", None))

        self.log = logger(str(self.state.get("ltID","")).encode("hex")[:10], "client")
        
        try:
            self.state["numservers"] = len(state["standard"]["lookupServers"])
        except:
            self.state["numservers"] = numservers

        try:
            self.state["numserversCB"] = len(state["combined"]["lookupServers"])
        except:
            self.state["numserversCB"] = numservers

        try:
            self.state["epoch_length"] = int(state["standard"]["epochLength"])
        except:
            self.state["epoch_length"] = 60

        try:
            self.state["epoch_lengthCB"] = int(state["combined"]["epochLength"])
        except:
            self.state["epoch_lengthCB"] = 10

        try:
            self.state["data_length"] = len(state["standard"]["dataEncSize"])
        except:
            self.state["data_length"] = 16 + self.bls.pub_size()
        assert (16 + self.bls.pub_size()) == self.state["data_length"]

        try:
            self.state["data_lengthCB"] = len(state["combined"]["dataEncSize"])
        except:
            self.state["data_lengthCB"] = 32
        assert self.state["data_lengthCB"] > 16

        ## TODO: Remove magic number 16 (MAC length)
        ## TODO: Allow for configurable dynamic periods

        self.config = DP5Config(self.state["epoch_length"], self.state["data_length"], False)
        self.configCB = DP5Config(self.state["epoch_lengthCB"], self.state["data_lengthCB"], True)
        
        ## Check any input data
        if "data" not in self.state:
            self.state["data"] = "\x00" * self.configCB.dataplain_bytes()
        else:
            assert len(self.state["data"]) == self.configCB.dataplain_bytes()

        self.event_handlers = {}
        self.register_handlers = []
        self.lookup_handlers = []

        self.active_requests = []
        self.seq_requests = 0

        self.seq_handlers = 0

        self.cbhandlerID = {}
        self.actionID = 0

        self.pool = None
        self.inflight = None

        aID = self.next_actionID()
        self.fire_event(("CLIENT","START"), aID)

    DEBUG_fake_epochCB = None
    def epochCB(self):
        if self.DEBUG_fake_epochCB:
            return self.DEBUG_fake_epochCB
        return self.configCB.current_epoch()

    DEBUG_fake_epoch = None
    def epoch(self):
        if self.DEBUG_fake_epoch:
            return self.DEBUG_fake_epoch
        return self.config.current_epoch()

    def next_actionID(self):
        aID = self.actionID
        self.actionID += 1
        return aID

    def set_active(self, label, aID):
        # self.seq_requests += 1
        self.active_requests += [(label, aID)]

        try:
            conn_num = sum([len(x) for x in self.pool.__dict__["_connections"]])
            self.log.log(("CONNECTION POOL", str(conn_num)), aID)
        except:
            self.log.log(("CONNECTION POOL", "???"""), aID)

        self.log.log(("INFLIGHT", str(self.inflight)), aID)
        self.log.log(("ACTIVE ON", str(len(self.active_requests))), aID)
        return aID

    def check_active(self, label, ID=None):
        # print len(self.active_requests), self.active_requests[:-5]
        for (l, i) in self.active_requests:
            match = True
            match =  match and l == label
            if ID != None:
                match = match and i == ID
            if match:
                return True
        return False

    def remove_active(self, label, ID):
        if (label, ID) in self.active_requests:
            self.log.log(("ACTIVE OFF", str(len(self.active_requests))), ID)
            self.active_requests.remove((label, ID))

    def set_event_handler(self, handler):
        self.seq_handlers += 1
        self.event_handlers[self.seq_handlers] = handler
        return self.seq_handlers

    def remove_event_handler(self, hID):
        if hID in self.event_handlers:
            del self.event_handlers[hID]

    def fire_event(self, event, aID = None):
        self.log.log(event, aID)
        for hid, e in self.event_handlers.items():
            e(self.state, event, hid=hid)
        

    def init_ID(self, data=None):
        self.ltID = DHKeys()
        if data is None:
            self.ltID.gen()
        else:
            self.ltID.frombuffer(data)
        self.state["ltID"] = self.ltID.tobuffer()

    def init_BLS(self, data = None):
        self.bls = BLSKeys()
        if data is None:
            self.bls.gen()
        else:
            self.bls.frombuffer(data)
        self.state["bls"] = self.bls.tobuffer()

    def get_pub(self):
        return self.ltID.pub()

    def set_friend(self, ltID, nick):
        if "friends" not in self.state:
            self.state["friends"] = {}

        friends = self.state["friends"]
        
        ## nick = None means delete friend
        if ltID in friends:
            if nick is None:
                del friends[ltID]
                return
            else: 
                friends[ltID]["nick"] = nick
                pass

        if ltID not in friends:
            friends[ltID] = {}
            friends[ltID]["nick"] = nick
            friends[ltID]["ltID"] = ltID
            friends[ltID]["epoch_cbID"] = None
            friends[ltID]["cbID"] = None
            friends[ltID]["last_on_line"] = None
            friends[ltID]["data"] = None
        else:
            friends[ltID]["nick"] = nick

    def register_ID(self, epoch = None):
        if epoch == None:
            # By default we register for the next epoch
            epoch = self.epoch()
        epoch = epoch + 1

        ## Do not re-enter
        label = ("REGID", epoch)
        if self.check_active(label):
            return

        aID = self.next_actionID()
        reqID = self.set_active(label, aID)
        self.fire_event(("REGID", "START"), aID)
        self.fire_event(("REGID", "EPOCH", str(epoch)), aID)

        ## First of all generate a fresh BLS Key
        friends = self.state.get("friends", [])
        pks = [self.ltID.pub()] ## Always include our own
        for f in friends:
            pks += [friends[f]["ltID"]]
        self.fire_event(("REGID","DEBUG", "FRIENDS%03d" % len(pks)), aID)


        reg = DP5ClientReg(self.config, self.ltID, pks, epoch)
        req = reg.register(self.bls.pub())

        def reply_callback(msg):
            if not self.check_active(label, reqID):
                self.fire_event(("REGID","INACTIVE"), aID)
                return
            try:
                reg.finish(msg)
                self.state["last_register_epoch"] = epoch
                self.remove_active(label, reqID)
                self.fire_event(("REGID","SUCCESS"), aID)
            except DP5Exception as e:
                self.remove_active(label, reqID)
                self.fire_event(("REGID","FAIL"), aID)

        def fail_callback(exp):
            if not self.check_active(label, reqID):
                self.fire_event(("REGID","INACTIVE_FAIL"), aID)
                return
            ## We do want to see this exception
            print exp
            self.remove_active(label, reqID)
            self.fire_event(("REGID","NETFAIL"), aID)

        # Call the network handlers
        if epoch == self.epoch() + 1:
            self.fire_event(("REGID","SEND"), aID)
            self.send_registration(epoch, False, req, reply_callback, fail_callback)
        else:
            print "ERROR:", epoch, self.epoch() + 1
            self.remove_active(label, reqID)
            self.fire_event(("REGID","TOOLATE"), aID)
        
        return req, reply_callback, fail_callback

    def register_combined(self, userdata, epoch = None):
        if epoch == None:
            # By default we register for the next epoch
            epoch = self.epochCB()
        epoch = epoch + 1

        ## Do not re-enter
        label = ("REGCB", epoch)
        if self.check_active(label):
            return

        aID = self.next_actionID()
        reqID = self.set_active(label, aID)
        self.fire_event(("REGCB","START"), aID)
        self.fire_event(("REGCB", "EPOCH", str(epoch)), aID)


        reg = DP5CombinedClientReg(self.configCB, self.bls, epoch)
        msg = reg.register(userdata)

        def reply_callback(msg):
            if not self.check_active(label, reqID):
                return
            try:
                reg.finish(msg)
                self.state["last_combined_epoch"] = epoch
                self.remove_active(label, reqID)
                self.fire_event(("REGCB","SUCCESS"), aID)
            except DP5Exception as e:
                self.remove_active(label, reqID)
                self.fire_event(("REGCB","EXCEPTION", e.msg), aID)
                self.fire_event(("REGCB","FAIL"), aID)

        def fail_callback(exp):
            if not self.check_active(label, reqID):
                return
            ## We do want to see this exception
            ## print exp
            self.remove_active(label, reqID)
            self.fire_event(("REGCB","NETFAIL"), aID)

        if epoch == self.epochCB() + 1:    
            self.fire_event(("REGCB","SEND"), aID)
            self.send_registration(epoch, True, msg, reply_callback, fail_callback)
        else:
            self.remove_active(label, reqID)
            self.fire_event(("REGCB","TOOLATE"), aID)
        return msg, reply_callback, fail_callback

    def lookup_ID(self, epoch = None):
        if epoch == None:
            # By default we register for the next epoch
            epoch = self.epoch()

        ## Do not re-enter
        label = ("LOOKID", epoch)
        if self.check_active(label):
            # print "Is already active", label
            return

        ## Now check if any previous epochs are active
        ## Only allow one epoch lookup in flight!
        last_epoch = self.state.get("last_lookup_epoch")
        if last_epoch is not None:
            for prev_epoch in range(last_epoch, epoch):
                prev_label = ("LOOKID", prev_epoch)
                if self.check_active(prev_label):
                    # print "Is already active", label
                    return

        aID = self.next_actionID()            
        reqID = self.set_active(label, aID)

        self.fire_event(("METAID","START"), aID)
        self.fire_event(("METAID", "EPOCH", str(epoch)), aID)

        friends = self.state.get("friends", [])
        pks = [self.ltID.pub()] ## Always include our own
        for f in friends:
                pks += [friends[f]["ltID"]]
        self.fire_event(("LOOKID","DEBUG", "FRIENDS%03d" % len(pks)), aID)


        lookup = DP5lookup( self.ltID, pks, epoch )
        meta_msg = lookup.metadata_request()

        SERVER_NUM = self.state["numservers"] 
        replies = []        

        def metafail_callback(exp):
            if not self.check_active(label, reqID):
                return
            # We do want to see this exception
            print exp
            self.remove_active(label, reqID)
            self.fire_event(("LOOKID","NETFAIL"), aID)

        def lookup_callback(msg):
            if not self.check_active(label, reqID):
                return

            replies.append(msg)
            if len(replies) == SERVER_NUM:
                try:
                    presence = lookup.lookup_reply(replies)
                    self.state["last_lookup_epoch"] = epoch
                    for (kx, online, msg) in presence:
                        if kx in friends:
                            if online:                                
                                friends[kx]["cbID"] = str(msg)
                                assert len(friends[kx]["cbID"]) == len(self.bls.pub())
                                friends[kx]["epoch_cbID"] = epoch
                    self.remove_active(label, reqID)
                    self.fire_event(("LOOKID","EPOCH", str(epoch), str(self.epoch())), aID)
                    self.fire_event(("LOOKID","SUCCESS"), aID)

                except DP5Exception as e:
                    ## Be a bit more granular:
                    if e.msg[1] == 0x18: ## No DB returned
                        self.remove_active(label, reqID)
                        self.fire_event(("LOOKID","EMPTYDB"), aID)
                    else:
                        print "Lookup Error", hex(e.msg[1])
                        print "Last Epoch", str(self.state.get("last_lookup_epoch",None)), "***"
                        print "Current epoch (in lookup)", epoch
			print "Current epoch (fresh)", self.epoch()

                        traceback.print_exc()
                        self.remove_active(label, reqID)
                        self.fire_event(("LOOKID","FAIL"), aID)

        def metareply_callback(msg):
            if not self.check_active(label, reqID):
                return
            try:
                lookup.metadata_reply(msg)
                self.state["last_meta_epoch"] = epoch

                self.fire_event(("LOOKID","START"), aID)
                self.fire_event(("LOOKID", "EPOCH", str(epoch)), aID)

                messages = lookup.lookup_request(SERVER_NUM)
                for seq, mx in enumerate(messages):
                    self.fire_event(("LOOKID","SEND%02d" % seq, "LEN%04d" % len(mx)), aID)
                    self.send_lookup(epoch, False, seq, mx, lookup_callback, metafail_callback)

                return messages, lookup_callback, metafail_callback

            except DP5Exception as e:
                print "Lookup Error (Meta ID)", e.msg
                print "Request Epoch", epoch
                print "Current Epoch", self.epoch()
                traceback.print_exc()

                self.remove_active(label, reqID)
                self.fire_event(("METAID","FAIL"), aID)

        seq = random.randint(0, SERVER_NUM-1)
        self.fire_event(("METAID","SEND"), aID)
        self.send_lookup(epoch, False, seq, meta_msg, metareply_callback, metafail_callback)
        return meta_msg, metareply_callback, metafail_callback

    def lookup_combined(self, epoch = None):
        if epoch == None:
            # By default we register for the next epoch
            epoch = self.epochCB()

        ## Do not re-enter
        label = ("LOOKCB", epoch)
        if self.check_active(label):
            # print "CB already active"
            return

        aID = self.next_actionID()
        reqID = self.set_active(label, aID)

        self.fire_event(("METACB","START"), aID)
        self.fire_event(("METACB", "EPOCH", str(epoch)), aID)

        friends = self.state.get("friends", [])
        pks = [self.bls.pub()] ## Always include our own
        cbmap = {}
        count = 0 
        for f in friends:
            if "cbID" in friends[f] and friends[f]["cbID"] != None:
                kcb = friends[f]["cbID"]
                count += 1
                cbmap[kcb] = friends[f]
                pks += [kcb]

        lookup = DP5Combinedlookup( self.bls, pks, epoch )
        meta_msg = lookup.metadata_request()

        SERVER_NUM = self.state["numserversCB"]  
        replies = []        

        def metafail_callback(exp):
            if not self.check_active(label, reqID):
                self.fire_event(("LOOKCB","INACTIVE"), aID)
                return
            
            print "META FAIL Exception:"
            print exp
            self.remove_active(label, reqID)
            self.fire_event(("LOOKCB","NETFAIL"), aID)

        def lookup_callback(msg):
            if not self.check_active(label, reqID):
                self.fire_event(("LOOKCB","INACTIVE"), aID)
                return
            replies.append(msg)
            if len(replies) == SERVER_NUM:
                try:
                    presence = lookup.lookup_reply(replies)
                    self.state["last_lookupcb_epoch"] = epoch
                    for (kx, online, msg) in presence:
                        if kx in cbmap:
                            if online:
                                cbmap[kx]["last_on_line"] = epoch
                                cbmap[kx]["data"] = msg

                    self.remove_active(label, reqID)
                    self.fire_event(("LOOKCB","SUCCESS"), aID)
                except DP5Exception as e:
                    print "Lookup CB Error", hex(e.msg[1])
                    traceback.print_exc()
                    self.remove_active(label, reqID)
                    self.fire_event(("LOOKCB","FAIL"), aID)


        def metareply_callback(msg):
            if not self.check_active(label, reqID):
                return
            try:
                lookup.metadata_reply(msg)
                self.state["last_metacb_epoch"] = epoch

                self.fire_event(("LOOKCB","START"), aID)
                self.fire_event(("LOOKCB", "EPOCH", str(epoch)), aID)

                messages = lookup.lookup_request(SERVER_NUM)
                # print "message lengths",  messages

                for seq, mx in enumerate(messages):
                    self.fire_event(("LOOKCB","SEND%02d" % seq, "LEN%06d" % len(mx)), aID)
                    self.send_lookup(epoch, True, seq, str(mx), lookup_callback, metafail_callback)

                return messages, lookup_callback, metafail_callback

            except DP5Exception as e:
                
                self.remove_active(label, reqID)
                self.fire_event(("METACB","FAIL"), aID)
                

        seq = random.randint(0, SERVER_NUM-1)
        self.fire_event(("METACB","SEND"), aID)
        self.send_lookup(epoch, True, seq, meta_msg, metareply_callback, metafail_callback)
        
        return meta_msg, metareply_callback, metafail_callback

    # Send registration messages through the (twisted) network code
    def send_registration(self, epoch, combined, msg, cb, fail):
        for h in self.register_handlers:
            h(self, epoch, combined, msg, cb, fail)

   # Send lookup messages through the (twisted) network code
    def send_lookup(self, epoch, combined, seq, msg, cb, fail):
        for h in self.lookup_handlers:
            h(self, epoch, combined, seq, msg, cb, fail)

    def update(self, epoch=None, epochcb=None, data = None):
        if data != None:
            self.state["data"] = data
            assert len(self.state["data"]) == self.configCB.dataplain_bytes()

        if epochcb == None:
            epochcb = self.epochCB()

        if epoch == None:
            epoch = self.epoch()
        
        ## First check whether we have registered for the next epoch.
        try:
            if self.state.get("last_register_epoch", 0) < epoch + 1:
                self.register_ID(epoch)
        except DP5Exception as e:
            ## TODO: Log error
            traceback.print_exc()
            ## ... and the show goes on ...

        try:
            if self.state.get("last_combined_epoch",0) < epochcb + 1:
                self.register_combined(self.state["data"], epochcb)
        except DP5Exception as e:
            ## TODO: Log error
            traceback.print_exc()
            ## ... and the show goes on ...

        ## Rudimentary cap on the in-flight requests
        if self.inflight > 5:
            return

        ## Then read the stuff from this epoch
        if self.state.get("last_lookup_epoch", 0) < epoch:

            ## Register a handler to triger the combined lookup
            def handler(state, event, hid=None):
                # print event
                if self.cbhandlerID[epoch] == hid:
                    if (event[0] == "LOOKID") and (event[1] == "SUCCESS"):

                        if self.state.get("last_lookup_epoch", 0) >= epoch:
                            self.update( epoch, epochcb, data)
                    
                    self.remove_event_handler(self.cbhandlerID[epoch])
                    del self.cbhandlerID[epoch]

                    
            if epoch not in self.cbhandlerID:
                self.cbhandlerID[epoch] = self.set_event_handler(handler)

                try:
                    self.lookup_ID(epoch)
                except DP5Exception as e:
                    ## TODO: Log error
                    traceback.print_exc()
                    ## ... and the show goes on ...
        else:
            if self.state.get("last_lookupcb_epoch", 0) < epochcb:
                # print "Perform a combined lookup only"

                try:
                    self.lookup_combined(epochcb)
                except DP5Exception as e:
                    ## TODO: Log error
                    traceback.print_exc()
                    ## ... and the show goes on ...

