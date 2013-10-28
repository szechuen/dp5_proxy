from dp5cffi import *
from dp5clib import *
from dp5asyncclient import *

## ------- Tests -----------------------

import unittest
import shutil
import os

class DP5TestCase(unittest.TestCase):
    def setUp(self):
        InitLib()

        try:
            shutil.rmtree("regdirpy")
        except Exception, e:
            pass

        try:
            shutil.rmtree("datadirpy")
        except Exception, e:
            pass

        try:
            shutil.rmtree("regdirCBpy")
        except Exception, e:
            pass

        try:
            shutil.rmtree("datadirCBpy")
        except Exception, e:
            pass

        try:
            os.remove("metadatapy.dat")
        except:
            pass
        try:
            os.remove("datapy.dat")
        except:
            pass

        try:
            os.remove("metadataCBpy.dat")
        except:
            pass
        try:
            os.remove("dataCBpy.dat")
        except:
            pass

        os.mkdir("regdirpy")
        os.mkdir("datadirpy")
        os.mkdir("regdirCBpy")
        os.mkdir("datadirCBpy")


    def tearDown(self):
        ## Delete all files in server directories
        shutil.rmtree("regdirpy")
        shutil.rmtree("datadirpy")
        shutil.rmtree("regdirCBpy")
        shutil.rmtree("datadirCBpy")
        try:
            os.remove("metadatapy.dat")
        except:
            pass
        try:
            os.remove("datapy.dat")
        except:
            pass

        try:
            os.remove("metadataCBpy.dat")
        except:
            pass
        try:
            os.remove("dataCBpy.dat")
        except:
            pass

    def test_raw_DHKey(self):
        # Using raw C functions
        x = C.DHKey_alloc();
        C.DHKey_keygen(x)
        xbuf = ffi.buffer(x, C.DHKey_size())
        self.assertEqual( len(xbuf), 2 * 32)
        C.DHKey_free(x)

    def test_py_DHKey(self):
        # Using the wrapper
        dhpy = DHKeys()
        dhpy.gen()
        self.assertEqual( dhpy.size(), 2*32 )
        self.assertEqual( dhpy.pub_size(), 32)
        self.assertEqual( len(dhpy.pub()), 32)
        b =  dhpy.tobuffer()
        dhpy.frombuffer(b)
        b2 =  dhpy.tobuffer()
        self.assertEqual( b, b2)
        del dhpy

    def test_raw_BLS(self):
        # Using raw C functions
        b = C.BLSKey_alloc();
        self.assertEqual( C.BLSKey_size(), 96)
        C.BLSKey_keygen(b)
        xbuf = ffi.buffer(b, C.BLSKey_size())
        C.BLSKey_free(b)

    def test_py_BLS(self):
        # Using the wrapper
        blspy = BLSKeys()
        blspy.gen()
        self.assertEqual( blspy.size(), 96)
        self.assertEqual( blspy.pub_size(), 64)
        self.assertEqual( len(blspy.pub()), 64)
        del blspy

    def test_raw_config(self):
        # Using raw C calls
        config = C.Config_alloc(1800, 32, False)
        self.assertEqual( C.Config_dataplain_bytes(config), 16)
        self.assertTrue( type(int(C.Config_current_epoch(config))) == type(0) )
        C.Config_delete(config)

    def test_py_config(self):
        # Using wrapper
        pyconfig = DP5Config(1800, 32, False)
        self.assertEqual(pyconfig.dataplain_bytes(), 16)
        epoch = pyconfig.current_epoch()
        del pyconfig

    def test_raw_registration(self):
        # libstate = C.Init_init()
        InitLib()

        # print "Start Reg client"
        keys = C.DHKey_alloc();
        config = C.Config_alloc(1800, 32, False)
        C.DHKey_keygen(keys)
        reg = C.RegClient_alloc(config, keys)

        ## Make 10 budies and create a buffer 
        # data buffer for them. This is the first
        # Python heavy lifting.
        friends_num = 10
        PKl = C.DHKey_pubsize()
        Dl = C.Config_dataplain_bytes(config)
        RECl = PKl + Dl
        data = ffi.new("char[]", friends_num*RECl)
        datab = ffi.buffer(data)

        for x in range(friends_num):
            fk_p = C.DHKey_alloc()
            fk = ffi.buffer(fk_p, C.DHKey_size())
            datab[x*RECl:x*RECl+PKl] = fk[:PKl]
            d = str(0x99) + "Hello"
            d = d + str(0x00) * (Dl - len(d))
            datab[x*RECl+PKl:(x+1)*RECl] = d
            C.DHKey_free(fk_p)

        datax, process_buffer = callbackbuffer()

        epoch = C.Config_current_epoch(config)
        err = C.RegClient_start(
            reg, config, epoch+1,
            friends_num, data, 
            process_buffer)
        self.assertEqual( int(err) , 0 )



        server = C.RegServer_alloc(config, epoch, "regdirpy", "datadirpy")


        mem = datax[0]
        buf = NativeBuf(mem)
        C.RegServer_register(server, buf.get(), process_buffer)

        mem = datax[1]
        buf = NativeBuf(mem)
        err = C.RegClient_complete(reg, epoch+1, buf.get())
        self.assertEqual( err , 0)

        e = C.RegServer_epoch_change(server, "metadatapy.dat", "datapy.dat")

    def test_client_reg1(self):
        state = {}
        cli = AsyncDP5Client(state)

        def handler(state, event):
            self.assertEqual( event , ("REGID","SUCCESS"))

        cli.set_event_handler(handler)

        for i in range(10):
            k = DHKeys()
            k.gen()
            cli.set_friend(k.pub(), "Friend %s" % i)

        msg, cb, nf = cli.register_ID()

        ## RAW server code
        epoch = C.Config_current_epoch(cli.config.get_ptr())
        server = C.RegServer_alloc(cli.config.get_ptr(), epoch, "regdirpy", "datadirpy")

        datax, process_buffer = callbackbuffer()
        buf = NativeBuf(msg)
        C.RegServer_register(server, buf.get(), process_buffer)
        reply = datax[0]

        cb(reply)

        C.RegServer_delete(server)

    def test_client_nosync(self):
        state = {}
        cli = AsyncDP5Client(state)

        def handler(state, event):
            self.assertEqual( event , ("REGID","FAIL"))

        cli.set_event_handler(handler)

        for i in range(10):
            k = DHKeys()
            k.gen()
            cli.set_friend(k.pub(), "Friend %s" % i)

        msg, cb, nf = cli.register_ID()

        ## Check that it will refuse to re-enter
        xx = cli.register_ID()
        self.assertEquals(xx, None)

        ## RAW server code
        epoch = C.Config_current_epoch(cli.config.get_ptr())
        server = C.RegServer_alloc(cli.config.get_ptr(), epoch+5, "regdirpy", "datadirpy")

        datax, process_buffer = callbackbuffer()
        buf = NativeBuf(msg)
        C.RegServer_register(server, buf.get(), process_buffer)
        reply = datax[0]

        cb(reply)

        C.RegServer_delete(server)

    def test_client_reg_combined(self):
        state = {}
        cli = AsyncDP5Client(state)

        def handler(state, event):
            self.assertEqual( event , ("REGCB","SUCCESS"))            

        cli.set_event_handler(handler)

        for i in range(10):
            k = DHKeys()
            k.gen()
            cli.set_friend(k.pub(), "Friend %s" % i)

        msg, cb, nf = cli.register_combined(" "*16)

        ## RAW server code
        epoch = C.Config_current_epoch(cli.configCB.get_ptr())
        server = C.RegServer_alloc(cli.configCB.get_ptr(), epoch, "regdirpy", "datadirpy")

        datax, process_buffer = callbackbuffer()
        buf = NativeBuf(msg)
        C.RegServer_register(server, buf.get(), process_buffer)
        reply = datax[0]

        cb(reply)

        C.RegServer_delete(server)

    def test_lookup(self):
        
        clients = []
        for i in range(10):
            state = {}
            cli = AsyncDP5Client(state)
            clients += [cli]

        for i in range(10):
            for j in range(5):
                clients[i].set_friend(clients[j].get_pub(), "Friend %s" % j)
                clients[j].set_friend(clients[i].get_pub(), "Friend %s" % i)

        ## RAW server code
        cli0 = clients[0]

        CALLED = [False]
        def handler(state, event):
            CALLED[0] = True
            self.assertEqual( event , ("LOOKID","SUCCESS"))

        cli0.set_event_handler(handler)

        epoch = cli0.config.current_epoch()
        server = RegServer(cli0.config, "regdirpy", "datadirpy")

        for i in range(4,8):
            cli = clients[i]
            msg, cb, nf = cli.register_ID()
            reply = server.register(msg)
            cb(reply)

        server.epoch_change("metadatapy.dat", "datapy.dat")

        ## Test lookup
        msg, success, failure = cli0.lookup_ID(epoch+1)
        lookup_server = LookupServer("metadatapy.dat", "datapy.dat")

        reply = lookup_server.process(msg)
        messages, success, failure = success(reply)

        for m in messages:
            if len(m) == 0:
                success("")
            else:
                reply = lookup_server.process(m)                
                success(reply)

        self.assertTrue( CALLED[0] )

    def test_nethandler(self):
        
        clients = []
        for i in range(10):
            state = {}
            cli = AsyncDP5Client(state)
            clients += [cli]

        for i in range(10):
            for j in range(5):
                clients[i].set_friend(clients[j].get_pub(), "Friend %s" % j)

        
        cli0 = clients[0]

        ## Initialize servers
        epoch = cli0.config.current_epoch()
        server = RegServer(cli0.config, "regdirpy", "datadirpy")

        ## Register 2 network handlers
        def send_registration(cli, epoch, combined, msg, cb, fail):
            reply = server.register(msg)
            cb(reply)

        for i in range(10):
            cli = clients[i]
            cli.register_handlers += [send_registration]

        CALLED = [False]
        def handler(state, event):
            CALLED[0] = True
            self.assertEqual( event , ("LOOKID","SUCCESS"))

        cli0.set_event_handler(handler)

        for i in range(4,8):
            cli = clients[i]
            msg, cb, nf = cli.register_ID()

        server.epoch_change("metadatapy.dat", "datapy.dat")

        lookup_server = LookupServer("metadatapy.dat", "datapy.dat")
        def send_lookup(cli, epoch, combined, seq, msg, cb, fail):
            if msg == "":
                cb("")
            else:
                reply = lookup_server.process(msg)
                cb(reply)

        for i in range(10):
            cli = clients[i]
            cli.lookup_handlers += [send_lookup]

        ## Test lookup
        msg, success, failure = cli0.lookup_ID(epoch+1)        

        self.assertTrue( CALLED[0] )

    def test_update(self):
        bls = BLSKeys()
        config = DP5Config(1800, 16 + bls.pub_size(), False)
        configCB = DP5Config(1800 / 6, 16 + 16, True)
        #epoch = config.current_epoch() + 1000
        #epochCB = configCB.current_epoch() + 1000

        epoch = 9000
        epochCB = 10000

        ## Make some clients
        clients = []
        for i in range(10):
            state = {}
            cli = AsyncDP5Client(state)
            cli.online = False
            clients += [cli]

        for i in range(10):
            for j in range(5):
                clients[i].set_friend(clients[j].get_pub(), "Friend %s" % j)
                clients[j].set_friend(clients[i].get_pub(), "Friend %s" % i)

        ## First create the ID infrastructure
        server = RegServer(config, "regdirpy", "datadirpy", epoch-1)
        serverCB = RegServer(configCB, "regdirCBpy", "datadirCBpy", epochCB-1)

        def send_registration(cli, epoch, combined, msg, cb, fail):
            if combined:
                reply = serverCB.register(msg)
                cb(reply)
            else:
                reply = server.register(msg)
                cb(reply)

        for i in range(3,7):
            cli = clients[i]
            cli.online = True
            cli.register_handlers += [send_registration]

            cli.register_ID(epoch-1)
            cli.register_combined(" "*16, epochCB-1)

        server.epoch_change("metadatapy.dat", "datapy.dat")
        serverCB.epoch_change("metadataCBpy.dat", "dataCBpy.dat")

        lookup_server = LookupServer("metadatapy.dat", "datapy.dat")
        lookup_serverCB = LookupServer("metadataCBpy.dat", "dataCBpy.dat")

        def send_lookup(cli, epoch, combined, seq, msg, cb, fail):
            if msg == "":
                cb("")
            else:
                if combined:
                    reply = lookup_serverCB.process(msg)
                    cb(reply)
                else:
                    reply = lookup_server.process(msg)
                    cb(reply)

        for i in range(10):
            clients[i].lookup_handlers += [send_lookup]        

        CALLED = [False]
        def handler(state, event):
            CALLED[0] = True
            
            self.assertEqual( event[1] , "SUCCESS")
            try:
                if event[0] == "LOOKID":
                    for i in range(10):
                            pk = clients[i].get_pub()
                            if pk in state["friends"]:
                                #print "ID Key:", (state["friends"][pk]["cbID"] != None), clients[i].online
                                self.assertEqual((state["friends"][pk]["cbID"] != None), clients[i].online)

                if event[0] == "LOOKCB":
                    for i in range(10):
                            pk = clients[i].get_pub()
                            if pk in state["friends"]:
                                if clients[i].online:
                                    self.assertEqual(state["friends"][pk].get("last_on_line", None), 10000)
                                else:
                                    self.assertEqual(state["friends"][pk].get("last_on_line", None), None)

            except Exception as e:
                print "FAIL", e

        for i in range(10):
            clients[i].set_event_handler(handler)


        for i in range(4,8):
            clients[i].update(epoch, epochCB)   

        return

if __name__ == "__main__":
    unittest.main(verbosity=2)
    pass
    