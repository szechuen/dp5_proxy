from dp5cffi import *

class DP5Config:
    def __init__(self, epoch_length, data_size, combined=False):
        self.epoch_length = epoch_length
        self.data_size = data_size
        self.combined = combined

        # Check inputs
        assert 0 < epoch_length 
        assert 16 < data_size

        self._config = C.Config_alloc(epoch_length, data_size, combined)

    def get_ptr(self):
        return self._config

    def current_epoch(self):
        epoch = C.Config_current_epoch(self._config)
        return int(epoch)

    def dataplain_bytes(self):
        dlen = C.Config_dataplain_bytes(self._config)
        return int(dlen)

    def __del__(self):
        C.Config_delete(self._config)

class CryptoKeys:
    def __init__(self):
        self.fun_init = None
        self.fun_gen = None
        self.fun_size = None
        self.fun_psize = None
        self.fun_free = None

        self.ptr = None

    def _init(self):
        assert self.ptr == None
        self.ptr = self.fun_init()

    def gen(self):
        self.fun_gen(self.ptr)

    def tobuffer(self):
        return buffer(ffi.buffer(self.ptr,self.size())[0:self.size()])

    def frombuffer(self, data):
        assert len(data) == self.size()
        ffi.buffer(self.ptr,self.size())[:] = data[:]

    def size(self):
        return int(self.fun_size())

    def pub_size(self):
        return int(self.fun_psize())

    def pub(self):
        b = ffi.buffer(self.ptr, self.size())[:self.pub_size()]
        return buffer(b)[:]

    def get_ptr(self):
        return self.ptr

    def __del__(self):
        self.fun_free(self.ptr)

class DHKeys(CryptoKeys):
    def __init__(self):
        self.fun_init = C.DHKey_alloc
        self.fun_gen = C.DHKey_keygen
        self.fun_size = C.DHKey_size
        self.fun_psize = C.DHKey_pubsize
        self.fun_free = C.DHKey_free

        self.ptr = None
        self._init()

class BLSKeys(CryptoKeys):
    def __init__(self):
        self.fun_init = C.BLSKey_alloc
        self.fun_gen = C.BLSKey_keygen
        self.fun_size = C.BLSKey_size
        self.fun_psize = C.BLSKey_pubsize
        self.fun_free = C.BLSKey_free

        self.ptr = None
        self._init()

class DP5ClientReg:
    def __init__(self, config, mykey, friendpubs, epoch):
        self.config = config
        self.mykey = mykey
        self.friendspubs = friendpubs
        self.epoch = epoch

        self.reg = C.RegClient_alloc(config.get_ptr(), mykey.get_ptr())

        for fpub in friendpubs:
            if len(fpub) != mykey.pub_size():
                raise Exception("Wrong public key length for friend")

    def register(self, payload):
        assert len(payload) == self.config.dataplain_bytes()

        data = ""
        for fpub in self.friendspubs:
            data += (fpub + payload)

        buf = ffi.new("char[]", len(data))
        ffi.buffer(buf)[:] = data[:]

        results, process_buffer = callbackbuffer()

        err = C.RegClient_start(
            self.reg, self.config.get_ptr(), self.epoch,
            len(self.friendspubs), buf, 
            process_buffer)

        if err != 0:
            raise Exception(("Regisration error", err))

        return results[0]

    def finish(self, msg):
        buf = NativeBuf(msg)
        err = C.RegClient_complete(self.reg, self.epoch, buf.get())
        if err != 0:
            raise Exception(("Regisration error", err))

    def __del__(self):
        C.RegClient_delete(self.reg)

class DP5CombinedClientReg:
    def __init__(self, config, mykey, epoch):
        self.config = config
        self.mykey = mykey
        self.epoch = epoch

        self.reg = C.RegClientCB_alloc(mykey.get_ptr())

    def register(self, payload):
        assert len(payload) == self.config.dataplain_bytes()

        results, process_buffer = callbackbuffer()
        buf = NativeBuf(payload)

        err = C.RegClientCB_start(
            self.reg, self.epoch, buf.get(), 
            process_buffer)

        if err != 0:
            raise Exception(("Regisration error", err))

        return results[0]

    def finish(self, msg):
        buf = NativeBuf(msg)
        err = C.RegClientCB_complete(self.reg, self.epoch, buf.get())
        if err != 0:
            raise Exception(("Regisration error", err))

    def __del__(self):
        C.RegClientCB_delete(self.reg)

class AsyncDP5Client:

    def __init__(self, state = None):
        self.state = state
        if state == None:
            state = {}

        self.init_ID(data=self.state.get("ltID",None))
        self.init_BLS(data=self.state.get("bls",None))

        ## TODO: Remove magic number 16 (MAC length)
        ## TODO: Allow for configurable periods
        self.config = DP5Config(1800, 16 + self.bls.pub_size(), False)
        self.configCB = DP5Config(1800 / 6, 16 + 16, True)

        self.event_handlers = []

    def fire_event(self, event):
        for e in self.event_handlers:
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
            print friends
            if nick is None:
                del friends[ltID]
                return
            else: 
                raise Exception("Trying to delete inexistant friend")

        if ltID not in friends:
            friends[ltID] = {}
            friends[ltID]["nick"] = nick
            friends[ltID]["ltID"] = ltID
            friends[ltID]["cbID"] = []
            friends[ltID]["online"] = []
            friends[ltID]["data"] = []
        else:
            friends[ltID]["nick"] = nick

    def register_ID(self, epoch = None):
        if epoch == None:
            # By default we register for the next epoch
            epoch = self.config.current_epoch()
        epoch = epoch + 1

        ## First of all generate a fresh BLS Key
        friends = self.state["friends"]
        pks = [self.ltID.pub()] ## Always include our own
        for f in friends:
            pks += [friends[f]["ltID"]]
        reg = DP5ClientReg(self.config, self.ltID, pks, epoch)
        req = reg.register(self.bls.pub())

        def reply_callback(msg):
            try:
                reg.finish(msg)
                self.state["last_register_epoch"] = epoch
                self.fire_event(("REGID","SUCCESS"))
            except:
                self.fire_event(("REGID","FAIL"))

        def fail_callback():
            self.fire_event(("REGID","NETFAIL"))


        return req, reply_callback, fail_callback

    def register_combined(self, userdata, epoch = None):
        if epoch == None:
            # By default we register for the next epoch
            epoch = self.configCB.current_epoch()
        epoch = epoch + 1

        reg = DP5CombinedClientReg(self.configCB, self.bls, epoch)
        msg = reg.register(userdata)

        def reply_callback(msg):
            try:
                reg.finish(msg)
                self.state["last_combined_epoch"] = epoch
                self.fire_event(("REGCB","SUCCESS"))
            except:
                self.fire_event(("REGCB","FAIL"))

        def fail_callback():
            self.fire_event(("REGCB","NETFAIL"))

        return msg, reply_callback, fail_callback

            





