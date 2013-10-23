from dp5cffi import *
from dp5clib import *

## ------- Tests -----------------------

import unittest

class DP5TestCase(unittest.TestCase):
    def setUp(self):
        InitLib()

    def tearDown(self):
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

        import os
        try:
            os.mkdir("regdirpy")
            os.mkdir("datadirpy")
        except Exception, e:
            pass

        server = C.RegServer_alloc(config, epoch, "regdirpy", "datadirpy")


        mem = datax[0]
        buf = NativeBuf(mem)
        C.RegServer_register(server, buf.get(), process_buffer)

        mem = datax[1]
        buf = NativeBuf(mem)
        err = C.RegClient_complete(reg, epoch+1, buf.get())
        self.assertEqual( err , 0)

        e = C.RegServer_epoch_change(server, "metadatapy.dat", "datapy.dat")

if __name__ == "__main__":
    unittest.main()
    pass
    