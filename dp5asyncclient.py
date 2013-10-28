## ---- Async client

from dp5clib import *
import random
import traceback



class AsyncDP5Client:

    def __init__(self, state = None, numservers=3):
        self.state = state
        if state == None:
            self.state = {}
        
        if not "numservers" in state:
            self.state["numservers"] = numservers

        self.init_ID(data=self.state.get("ltID",None))
        self.init_BLS(data=self.state.get("bls",None))

        ## TODO: Remove magic number 16 (MAC length)
        ## TODO: Allow for configurable periods
        self.config = DP5Config(1800, 16 + self.bls.pub_size(), False)
        self.configCB = DP5Config(1800 / 6, 16 + 16, True)

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

    def set_active(self, label):
        self.seq_requests += 1
        self.active_requests += [(label, self.seq_requests)]

    def check_active(self, label, ID=None):
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
            self.active_requests.remove((label, ID))

    def set_event_handler(self, handler):
        self.seq_handlers += 1
        self.event_handlers[self.seq_handlers] = handler
        return self.seq_handlers

    def remove_event_handler(self, hID):
        if hID in self.event_handlers:
            del self.event_handlers[hID]

    def fire_event(self, event):
        for e in self.event_handlers.values():
            e(self.state, event)

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
        self.state["bls"] = self.ltID.tobuffer()

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
            epoch = self.config.current_epoch()
        epoch = epoch + 1

        ## Do not re-enter
        label = ("REGID", epoch)
        if self.check_active(label):
            return
        reqID = self.set_active(label)

        ## First of all generate a fresh BLS Key
        friends = self.state["friends"]
        pks = [self.ltID.pub()] ## Always include our own
        for f in friends:
            pks += [friends[f]["ltID"]]
        reg = DP5ClientReg(self.config, self.ltID, pks, epoch)
        req = reg.register(self.bls.pub())

        def reply_callback(msg):
            if not self.check_active(label, reqID):
                return

            try:
                reg.finish(msg)
                self.state["last_register_epoch"] = epoch
                self.remove_active(label, reqID)
                self.fire_event(("REGID","SUCCESS"))
            except DP5Exception as e:
                self.remove_active(label, reqID)
                self.fire_event(("REGID","FAIL"))

        def fail_callback():
            if not self.check_active(label, reqID):
                return
            self.remove_active(label, reqID)
            self.fire_event(("REGID","NETFAIL"))

        # Call the network handlers
        self.send_registration(epoch, False, req, reply_callback, fail_callback)

        return req, reply_callback, fail_callback

    def register_combined(self, userdata, epoch = None):
        if epoch == None:
            # By default we register for the next epoch
            epoch = self.configCB.current_epoch()
        epoch = epoch + 1

        ## Do not re-enter
        label = ("REGCB", epoch)
        if self.check_active(label):
            return
        reqID = self.set_active(label)

        reg = DP5CombinedClientReg(self.configCB, self.bls, epoch)
        msg = reg.register(userdata)

        def reply_callback(msg):
            if not self.check_active(label, reqID):
                return
            try:
                reg.finish(msg)
                self.state["last_combined_epoch"] = epoch
                self.remove_active(label, reqID)
                self.fire_event(("REGCB","SUCCESS"))
            except:
                self.remove_active(label, reqID)
                self.fire_event(("REGCB","FAIL"))

        def fail_callback():
            if not self.check_active(label, reqID):
                return
            self.remove_active(label, reqID)
            self.fire_event(("REGCB","NETFAIL"))

        self.send_registration(epoch, True, msg, reply_callback, fail_callback)
        return msg, reply_callback, fail_callback

    def lookup_ID(self, epoch = None):
        if epoch == None:
            # By default we register for the next epoch
            epoch = self.config.current_epoch()

        ## Do not re-enter
        label = ("LOOKID", epoch)
        if self.check_active(label):
            return
        reqID = self.set_active(label)

        friends = self.state["friends"]
        pks = [self.ltID.pub()] ## Always include our own
        for f in friends:
                pks += [friends[f]["ltID"]]

        lookup = DP5lookup( self.ltID, pks, epoch )
        meta_msg = lookup.metadata_request()

        SERVER_NUM = self.state["numservers"] 
        replies = []        

        def metafail_callback():
            if not self.check_active(label, reqID):
                return
            self.remove_active(label, reqID)
            self.fire_event(("LOOKID","NETFAIL"))

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
                    self.fire_event(("LOOKID","SUCCESS"))
                except DP5Exception as e:
                    print "Lookup Error", e.msg
                    traceback.print_exc()
                    self.remove_active(label, reqID)
                    self.fire_event(("LOOKID","FAIL"))

        def metareply_callback(msg):
            if not self.check_active(label, reqID):
                return
            try:
                lookup.metadata_reply(msg)
                self.state["last_meta_epoch"] = epoch

                messages = lookup.lookup_request(SERVER_NUM)
                for seq, mx in enumerate(messages):
                    self.send_lookup(epoch, False, seq, mx, lookup_callback, metafail_callback)

                return messages, lookup_callback, metafail_callback

            except DP5Exception as e:
                print "Lookup Error (Meta ID)", e.msg
                traceback.print_exc()
                self.remove_active(label, reqID)
                self.fire_event(("METAID","FAIL"))

        seq = random.randint(0, SERVER_NUM-1)
        self.send_lookup(epoch, False, seq, meta_msg, metareply_callback, metafail_callback)
        return meta_msg, metareply_callback, metafail_callback

    def lookup_combined(self, epoch = None):
        if epoch == None:
            # By default we register for the next epoch
            epoch = self.configCB.current_epoch()

        ## Do not re-enter
        label = ("LOOKCB", epoch)
        if self.check_active(label):
            return
        reqID = self.set_active(label)

        friends = self.state["friends"]
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

        SERVER_NUM = self.state["numservers"]  
        replies = []        

        def metafail_callback():
            if not self.check_active(label, reqID):
                return

            self.remove_active(label, reqID)
            self.fire_event(("LOOKCB","NETFAIL"))

        def lookup_callback(msg):
            if not self.check_active(label, reqID):
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
                    self.fire_event(("LOOKCB","SUCCESS"))
                except DP5Exception as e:
                    print "CB Lookup Error", e.msg

                    traceback.print_exc()
                    self.remove_active(label, reqID)
                    self.fire_event(("LOOKCB","FAIL"))


        def metareply_callback(msg):
            if not self.check_active(label, reqID):
                return
            try:
                lookup.metadata_reply(msg)
                self.state["last_metacb_epoch"] = epoch

                messages = lookup.lookup_request(SERVER_NUM)
                # print "message lengths",  messages

                for seq, mx in enumerate(messages):
                    self.send_lookup(epoch, True, seq, str(mx), lookup_callback, metafail_callback)

                return messages, lookup_callback, metafail_callback

            except DP5Exception, e:
                print "CB FAIL", e
                self.remove_active(label, reqID)
                self.fire_event(("METACB","FAIL"))
                

        seq = random.randint(0, SERVER_NUM-1)
        self.send_lookup(epoch, True, seq, meta_msg, metareply_callback, metafail_callback)
        
        return meta_msg, metareply_callback, metafail_callback

    def send_registration(self, epoch, combined, msg, cb, fail):
        for h in self.register_handlers:
            h(self, epoch, combined, msg, cb, fail)

    def send_lookup(self, epoch, combined, seq, msg, cb, fail):
        for h in self.lookup_handlers:
            h(self, epoch, combined, seq, msg, cb, fail)

    def update(self, epoch=None, epochcb=None, data = None):
        if data != None:
            self.state["data"] = data
            assert len(self.state["data"]) == self.configCB.dataplain_bytes()

        if epochcb == None:
            epochcb = self.configCB.current_epoch()
        if epoch == None:
            epoch = self.config.current_epoch()
        
        ## First check whether we have registered for the next epoch.
        if self.state.get("last_register_epoch",0) < epoch + 1:
            self.register_ID(epoch)

        if self.state.get("last_combined_epoch",0) < epochcb + 1:
            self.register_combined(self.state["data"], epochcb)

        ## Then read the stuff from this epoch
        if self.state.get("last_lookup_epoch",0) < epoch:            
            kID = [None]
            def handler(state, event):  
                if self.state.get("last_lookupcb_epoch", 0) < epochcb:
                    if self.state.get("last_lookup_epoch",0) == epoch:
                        self.update( epoch, epochcb, data)
                else:
                    self.remove_event_handler(kID[0])
                
            kID[0] = self.set_event_handler(handler)

            self.lookup_ID(epoch)
        else:
            if self.state.get("last_lookupcb_epoch", 0) < epochcb:
                self.lookup_combined(epochcb)






