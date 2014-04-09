from dp5cffi import *

class DP5Exception(Exception):
    def __init__(self, msg):
        self.msg = msg

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
    ptr = None
    generated = False
    def __init__(self):
        self.fun_init = None
        self.fun_gen = None
        self.fun_size = None
        self.fun_psize = None
        self.fun_free = None

        # self.ptr = None

    def _init(self):
        assert self.ptr == None
        self.ptr = self.fun_init()

    def gen(self):
        assert not self.generated
        self.fun_gen(self.ptr)
        self.generated = True

    def tobuffer(self):
        assert self.generated
        assert self.ptr is not None
        return str(buffer(ffi.buffer(self.ptr,self.size())[0:self.size()]))

    def frombuffer(self, data):
        assert len(data) == self.size()
        assert not self.generated
        assert self.ptr is not None
        ffi.buffer(self.ptr,self.size())[:] = data[:]
        self.generated = True

    def size(self):
        return int(self.fun_size())

    def pub_size(self):
        return int(self.fun_psize())

    def pub(self):
        assert self.generated
        assert self.ptr is not None
        b = ffi.buffer(self.ptr, self.size())[:self.pub_size()]
        return buffer(b)[:]

    def get_ptr(self):
        assert self.generated
        assert self.ptr is not None
        return self.ptr

    def __del__(self):
        assert self.ptr is not None
        self.fun_free(self.ptr)

class DHKeys(CryptoKeys):
    def __init__(self):
        self.fun_init = C.DHKey_alloc
        self.fun_gen = C.DHKey_keygen
        self.fun_size = C.DHKey_size
        self.fun_psize = C.DHKey_pubsize
        self.fun_free = C.DHKey_free

        self._init()

class BLSKeys(CryptoKeys):
    def __init__(self):
        self.fun_init = C.BLSKey_alloc
        self.fun_gen = C.BLSKey_keygen
        self.fun_size = C.BLSKey_size
        self.fun_psize = C.BLSKey_pubsize
        self.fun_free = C.BLSKey_free

        # self.ptr = None
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
                raise DP5Exception("Wrong public key length for friend")

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
            print "Registraton error code: ", hex(err)
            raise DP5Exception(("Regisration error", err))

        return results[0]

    def finish(self, msg):
        buf = NativeBuf(msg)
        err = C.RegClient_complete(self.reg, self.epoch, buf.get())
        if err != 0:
            raise DP5Exception(("Regisration error", err))

    def __del__(self):
        C.RegClient_delete(self.reg)

class DP5CombinedClientReg:
    def __init__(self, config, mykey, epoch):
        self.config = config
        self.mykey = mykey
        self.epoch = epoch

        self.reg = C.RegClientCB_alloc(mykey.get_ptr())

    def register(self, payload):
        if len(payload) != self.config.dataplain_bytes():
            raise DP5Exception("Wrong payload length")

        results, process_buffer = callbackbuffer()
        buf = NativeBuf(payload)

        err = C.RegClientCB_start(
            self.reg, self.epoch, buf.get(), 
            process_buffer)

        if err != 0:
            raise DP5Exception(("Regisration error", err))

        return results[0]

    def finish(self, msg):
        buf = NativeBuf(msg)
        err = C.RegClientCB_complete(self.reg, self.epoch, buf.get())
        if err != 0:
            raise DP5Exception(("Regisration error", err))

    def __del__(self):       
        C.RegClientCB_delete(self.reg)


class DP5lookup:
    def __init__(self, mykey, friendpubs, epoch):
        self.ptr = C.LookupClient_alloc(mykey.get_ptr())
        self.mykey = mykey
        self.friendspubs = friendpubs
        self.epoch = epoch
        self.req = None

    def metadata_request(self):
        results, process_buffer = callbackbuffer()
        C.LookupClient_metadata_req(self.ptr, self.epoch, process_buffer)
        return results[0]

    def metadata_reply(self, msg):
        buf = NativeBuf(msg)
        err = C.LookupClient_metadata_rep(self.ptr, buf.get())
        if err != 0:
            raise DP5Exception(("Lookup error", err))

    def lookup_request(self, num_servers):
        assert self.req is None

        data = ""
        for pk in self.friendspubs:
            data += pk

        buf = ffi.new("char[]", len(data))
        ffi.buffer(buf, len(data))[:] = data[:]
        results, process_buffer = callbackbuffer()

        friends_len = len(self.friendspubs)
        self.req = C.LookupRequest_lookup(self.ptr, friends_len, buf, num_servers, process_buffer)

        return results

    def lookup_reply(self, replies):

        returns = []

        @ffi.callback("void(char*, bool, size_t, void*)")
        def presence(pub, online, size, msg):            
            pub = str(ffi.buffer(pub, self.mykey.pub_size())[:])
            online = [False, True][online]
            status = None
            if online:
                status = str(ffi.buffer(msg, size)[:])

            returns.append((pub, online, status))

        ## WARNING: "live" variable below must be kept alive
        self.live = [NativeBuf(x) for x in replies]
        data = [b.get() for b in self.live]
        err = C.LookupRequest_reply(self.req, len(replies), data, presence)
        
        # means DB was empty
        if err == 0x18:
            return []

        if err != 0:
            raise DP5Exception(("Lookup Error", err))

        return returns

    def __del__(self):
        C.LookupClient_delete(self.ptr)
        if self.req != None:
            C.LookupRequest_delete(self.req)

class DP5Combinedlookup:
    def __init__(self, mykey, friendpubs, epoch):
        self.ptr = C.LookupClientCB_alloc()
        self.mykey = mykey
        self.friendspubs = friendpubs
        self.epoch = epoch
        self.req = None
        self.handles = None

        pk_size = len(mykey.pub())
        for fkey in friendpubs:
            if len(fkey) != pk_size:
                raise DP5Exception("Wrong BLS key size")

    def metadata_request(self):
        results, process_buffer = callbackbuffer()
        C.LookupClientCB_metadata_req(self.ptr, self.epoch, process_buffer)
        return results[0]

    def metadata_reply(self, msg):
        buf = NativeBuf(msg)
        err = C.LookupClientCB_metadata_rep(self.ptr, buf.get())
        if err != 0:
            raise DP5Exception(("Lookup error (Metadata)", err))

    def lookup_request(self, num_servers):
        assert self.req is None

        data = ""
        for pk in self.friendspubs:
            data += pk

        buf = ffi.new("char[]", data)
        results, process_buffer = callbackbuffer()

        friends_len = len(self.friendspubs)
        self.req = C.LookupRequestCB_lookup(self.ptr, friends_len, buf, num_servers, process_buffer)

        return results

    def lookup_reply(self, replies):

        returns = []

        @ffi.callback("void(char*, bool, size_t, void*)")
        def presence(pub, online, size, msg):            
            pub = str(ffi.buffer(pub, self.mykey.pub_size())[:])
            online = [False, True][online]
            status = None
            if online:
                status = str(ffi.buffer(msg, size)[:])

            returns.append((pub, online, status))

        ## WE NEED THIS VARIABLE TO KEEP THE MEMORY ALIVE
        self.handles = [NativeBuf(x) for x in replies]

        data = [h.get() for h in self.handles]
        err = C.LookupRequestCB_reply(self.req, len(replies), data, presence)

        # means DB was empty
        if err == 0x18:
            return []

        if err != 0:
            raise DP5Exception(("Lookup Error (Lookup)", err))

        return returns

    def __del__(self):
        C.LookupClientCB_delete(self.ptr)
        if self.req != None:
            C.LookupRequestCB_delete(self.req)

# ---- Some server helper functions

class RegServer:
    def __init__(self, config, regdir, datadir, epoch = None):
        if epoch == None:
            epoch = config.current_epoch()
        self.epoch = epoch
        self.server = C.RegServer_alloc(config.get_ptr(), self.epoch, regdir, datadir)

    def register(self, msg):
        datax, process_buffer = callbackbuffer()
        buf = NativeBuf(msg)
        C.RegServer_register(self.server, buf.get(), process_buffer)
        reply = datax[0]
        return reply

    def epoch_change(self, metafile, datafile):
        C.RegServer_epoch_change(self.server, metafile, datafile)

    def __del__(self):
        C.RegServer_delete(self.server)

class LookupServer:
    def __init__(self, metafile, datafile):
        self.server = C.LookupServer_alloc(metafile, datafile)

    def process(self, msg):
        datax, process_buffer = callbackbuffer()
        mem = NativeBuf(msg)
        C.LookupServer_process(self.server, mem.get(), process_buffer)

        return str(datax[0])

    def __del__(self):
        C.LookupServer_delete(self.server)





            





