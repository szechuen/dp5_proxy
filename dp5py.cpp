#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "dp5params.h"

#include "dp5regclient.h"
#include "dp5lookupclient.h"

#include "dp5regserver.h"
#include "dp5lookupserver.h"

#include "Pairing.h"

#include <fstream>

using namespace dp5;
// Python module compilation notes
//
// NTL: We need to compile NTL using Position-Independent-Code. Configure it as:
//      ./configure PREFIX=/usr/local/lib "CFLAGS=-O2 -fPIC"
//      When built make sure to copy the lib to /usr/local/lib by doing:
//      sudo cp ntl.a /usr/local/lib/libntl.a
//
// Percy: Also recompile with PIC by adding -fPIC to the CXX flags
//        CXXFLAGS= -fPIC -Wall -Wno-vla -Wno-long-long -g -O2 -pedantic -I/usr/local/include/NTL


extern "C" {

struct s_client {
    PrivKey privkey;
    PubKey pubkey;
    DP5RegClient * reg;
    DP5LookupClient * cli;
    DP5Config config;
    DP5LookupClient::Request req;
};

struct s_server {
    DP5RegServer * regs;
    DP5LookupServer * lookups;
    DP5Config config;
};


// ------------------------- Util & Crypto interfaces ----------

void config_delete(PyObject *self) {
    void * ptr = PyCapsule_GetPointer(self, "dp5_config");
    if (ptr != NULL)
        PyMem_Free(ptr);
}

static PyObject* pymake_config(PyObject* self, PyObject *args) {
    unsigned int epoch_len;
    unsigned int dataenc_bytes;
    PyObject *combined;
    int ok = PyArg_ParseTuple(args, "IIO", &epoch_len, &dataenc_bytes,
            &combined);
    if (!ok)
        return NULL;

    int isTrue = PyObject_IsTrue(combined);
    if (isTrue < 0)
        return NULL;

    DP5Config * config = static_cast<DP5Config *>
        (PyMem_Malloc(sizeof(*config)));
    if (!config)
        return NULL;

    config->epoch_len = epoch_len;
    config->dataenc_bytes = dataenc_bytes;
    config->combined = isTrue;

    PyObject *capsule = PyCapsule_New(static_cast<void *>(config),
        "dp5_config", &config_delete);
    return capsule;
}

static PyObject* pygenkeypair(PyObject* self, PyObject* args){
    PrivKey privkey;
    PubKey pubkey;
    genkeypair(pubkey, privkey);

    PyObject *ret = Py_BuildValue("(z#z#)",
                        (const byte *)pubkey, pubkey.size,
                        (const byte *)privkey, privkey.size);

    return ret;
}

static DP5Config * getConfig(PyObject *config_capsule) {
    if (!PyCapsule_IsValid(config_capsule, "dp5_config"))
        return NULL;

    return static_cast<DP5Config *>(PyCapsule_GetPointer(config_capsule,
        "dp5_config"));
}

static PyObject* pygetdatasize(PyObject* self, PyObject* args)
{
    PyObject *config_capsule;
    int ok = PyArg_ParseTuple(args, "O", &config_capsule);
    if (!ok)
        return NULL;

    DP5Config * config = getConfig(config_capsule);
    if (!config)
        return NULL;

    return PyInt_FromLong(config->dataenc_bytes);
}

static PyObject* pygetepoch(PyObject* self, PyObject* args){
    PyObject *config_capsule;
    int ok = PyArg_ParseTuple(args, "O", &config_capsule);
    if (!ok)
        return NULL;
    DP5Config * config = getConfig(config_capsule);
    if (!config)
        return NULL;

    return PyInt_FromLong(config->current_epoch());
}


// ---------------------- Client interfaces -------------------------

void client_delete(PyObject * self){
    s_client * c = (s_client *) PyCapsule_GetPointer(self, "dp5_client");
    delete c->cli;
    delete c->reg;
    delete c;
}

static PyObject* pygetnewclient(PyObject* self, PyObject* args){

    // Get a private key
    byte *privkey;
    Py_ssize_t keysize = 0;
    PyObject *config_capsule;

    int ok = PyArg_ParseTuple(args, "Oz#", &config_capsule, &privkey, &keysize);
    if (!ok || keysize != PrivKey::size) return NULL;
    DP5Config *config = getConfig(config_capsule);
    if (!config)
        return NULL;

    s_client * c = new s_client();
    c->privkey.assign(privkey, keysize);
    getpubkey(c->pubkey, c->privkey);
    c->config = *config;
    c->cli = new DP5LookupClient(c->privkey);
    c->reg = new DP5RegClient(c->config, c->privkey);

/*
    // Allocate a request in place
    // DP5LookupClient::Request * temp =
    new (&(c->req)) DP5LookupClient::Request();
*/

    PyObject * cap = PyCapsule_New(static_cast<void *>(c), "dp5_client",
        (PyCapsule_Destructor) &client_delete);

    return cap;
}

static PyObject* pyclientregstart(PyObject* self, PyObject* args){
    // We expect 2 arguments: an s_client and a buddy list
    PyObject* sclient;
    PyObject* buddielist;
    unsigned int next_epoch;
    int ok = PyArg_ParseTuple(args, "OIO", &sclient, &next_epoch, &buddielist);
    if (!ok) return NULL;
    if (!PyCapsule_CheckExact(sclient)) return NULL;
    if (!PyList_Check(buddielist)) return NULL;

    string result;
    vector<BuddyInfo> bs;

    s_client * c = (s_client *) PyCapsule_GetPointer(sclient, "dp5_client");
    if (!c){
         PyErr_SetString(PyExc_RuntimeError, "Bad capsule");
         return NULL;
    }

    for(unsigned int i = 0; i < PyList_Size(buddielist); i++)
    {
        PyObject * item = PyList_GetItem(buddielist, i);
        if (!item) {
            PyErr_SetString(PyExc_RuntimeError, "Item is null");
            return NULL; }

        PyObject * pubk = PySequence_GetItem(item,0);
        PyObject * data = PySequence_GetItem(item,1);
        if (!pubk || !PyString_Check(pubk) || !data || !PyString_Check(data)){
            PyErr_SetString(PyExc_RuntimeError, "Bad item format");
            return NULL;
        }

        // FIXME: dataencbytes will eventually not equal dataplain_bytes
        if (PyString_Size(pubk) != PubKey::size ||
                PyString_Size(data) != c->config.dataenc_bytes){
            PyObject_Print(item, stdout, 0);
            PyErr_SetString(PyExc_RuntimeError, "Bad item format");
            return NULL;  }

        BuddyInfo b;
        b.pubkey.assign(reinterpret_cast<const byte *>(PyString_AsString(pubk)), b.pubkey.size);
        b.data.assign(PyString_AsString(data), PyString_Size(data));
        bs.push_back(b);
    }

    ok = (c->reg)->start_reg(result, next_epoch, bs);
    if (ok != 0x00){
        printf("Error: %d\n", ok);
        PyErr_SetString(PyExc_RuntimeError, "Protocol interface error");
        return NULL;
    }
    PyObject *ret = Py_BuildValue("z#",
                        (char *)result.data(), result.length());
    return ret;
}

static PyObject* pyclientregcomplete(PyObject* self, PyObject* args){
    PyObject* sclient;
    unsigned int next_epoch;
    char *msg;
    Py_ssize_t msgsize = 0;
    int ok = PyArg_ParseTuple(args, "Oz#I", &sclient, &msg, &msgsize, &next_epoch);
    if (!ok) return NULL;
    if (!PyCapsule_CheckExact(sclient)) return NULL;

    string smsg;
    smsg.assign(msg, msgsize);

    s_client * c = (s_client *) PyCapsule_GetPointer(sclient, "dp5_client");
    if (!c){
         PyErr_SetString(PyExc_RuntimeError, "Bad capsule");
         return NULL;
    }
    ok = (c->reg)->complete_reg(smsg, next_epoch);
    if (ok != 0x00){
        printf("Error: %d\n",ok);
        PyErr_SetString(PyExc_RuntimeError, "Protocol interface error");
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject* pyclientmetadatarequest(PyObject* self, PyObject* args){
    PyObject* sclient;
    unsigned int epoch;

    int ok = PyArg_ParseTuple(args, "OI", &sclient, &epoch);
    if (!ok) return NULL;
    if (!PyCapsule_CheckExact(sclient)) return NULL;

    string result;

    s_client * c = (s_client *) PyCapsule_GetPointer(sclient, "dp5_client");
    if (!c){
         PyErr_SetString(PyExc_RuntimeError, "Bad capsule");
         return NULL;
    }

    (c->cli)->metadata_request(result, epoch);
    PyObject *ret = Py_BuildValue("z#",
                        (char *)result.data(), result.length());
    return ret;
}

static PyObject* pyclientmetadatareply(PyObject* self, PyObject* args){
    PyObject* sclient;
    char * data;
    Py_ssize_t datasize = 0;

    int ok = PyArg_ParseTuple(args, "Oz#", &sclient, &data, &datasize);
    if (!ok) return NULL;
    if (!PyCapsule_CheckExact(sclient)) return NULL;

    string datain;
    datain.assign(data, datasize);

    s_client * c = (s_client *) PyCapsule_GetPointer(sclient, "dp5_client");
    if (!c){
         PyErr_SetString(PyExc_RuntimeError, "Bad capsule");
         return NULL;
    }

    ok = (c->cli)->metadata_reply(datain);
    if (ok != 0x00) {
        printf("Error: %d\n",ok);
        PyErr_SetString(PyExc_RuntimeError, "Protocol interface error");
        return NULL; }

    Py_RETURN_NONE;
}

static PyObject* pyclientlookuprequest(PyObject* self, PyObject* args){
    // printf("Got to request... 1\n");
    PyObject* sclient;
    PyObject* buddies;
	unsigned int num_servers;
	unsigned int privacy;
    int ok = PyArg_ParseTuple(args, "OOII", &sclient, &buddies, &num_servers, &privacy);
    if (!ok) return NULL;
    if (!PyCapsule_CheckExact(sclient)) return NULL;
    if (!PyList_Check(buddies)) return NULL;

    s_client * c = (s_client *) PyCapsule_GetPointer(sclient, "dp5_client");
    if (!c){
         PyErr_SetString(PyExc_RuntimeError, "Bad capsule");
         return NULL;
    }

    vector<PubKey> buds;
    for(unsigned int i = 0; i < PyList_Size(buddies); i++)
    {
        PyObject * item = PyList_GetItem(buddies, i);
        if (!item || !PyString_Check(item)
                || PyString_Size(item) != PubKey::size) {
            PyErr_SetString(PyExc_RuntimeError,
                "Item is null or not a string or not the right length");
            return NULL; }

        PubKey pk;
        pk.assign(reinterpret_cast<const byte *>(
            PyString_AsString(item)), PyString_Size(item));
        buds.push_back(pk);
    }

    if (!(c->cli)) return NULL;

    ok = (c->cli)->lookup_request(c->req, buds, num_servers, privacy);
    if (ok != 0x00) return NULL;

    vector<string> msgCtoSpir = (c->req).get_msgs();

    PyObject* ret = PyList_New(msgCtoSpir.size());
    for (unsigned int i = 0; i < msgCtoSpir.size(); i++){
        if (msgCtoSpir[i].length() > 0) {
            PyList_SetItem(ret, i, PyString_FromStringAndSize(msgCtoSpir[i].data(), msgCtoSpir[i].length()));
        }
        else {
            PyList_SetItem(ret, i, Py_None);
        }
    }

    return ret;
}

static PyObject* pyclientlookupreply(PyObject* self, PyObject* args){
    PyObject* sclient;
    PyObject* incoming;
    int ok = PyArg_ParseTuple(args, "OO", &sclient, &incoming);
    if (!ok) return NULL;
    if (!PyCapsule_CheckExact(sclient)) return NULL;
    if (!PyList_Check(incoming)) return NULL;


    s_client * c = (s_client *) PyCapsule_GetPointer(sclient, "dp5_client");
    if (!c){
         PyErr_SetString(PyExc_RuntimeError, "Bad capsule");
         return NULL;
    }

    vector<string> msgStoCpir;
    for(unsigned int i = 0; i < PyList_Size(incoming); i++){
        PyObject * item = PyList_GetItem(incoming, i);
        if (PyString_Check(item)
                && PyString_Size(item) > 0) {
            string s;
            s.assign(PyString_AsString(item), PyString_Size(item));
            msgStoCpir.push_back(s);
        }
        else if (item == Py_None){
            msgStoCpir.push_back("");
        } else {
            PyErr_SetString(PyExc_RuntimeError, "Unknown object type in list");
            return NULL;
        }
    }

    vector<DP5LookupClient::Presence> presence;
    ok = (c->req).lookup_reply(presence, msgStoCpir);
    if (ok != 0x00) {
        printf("Error: %d\n",ok);
        PyErr_SetString(PyExc_RuntimeError, "Protocol interface error");
        return NULL;
    }

    PyObject* ret = PyList_New(presence.size());
    for( unsigned int i = 0; i < presence.size(); i++){
        if (presence[i].is_online) {
            PyObject * item = Py_BuildValue("z#Oz#",
                (const byte *) presence[i].pubkey, presence[i].pubkey.size,
                Py_True, presence[i].data.c_str(), presence[i].data.size());
            PyList_SetItem(ret, i, item); }
        else {
            PyObject * item = Py_BuildValue("z#OO",
                (const byte *) presence[i].pubkey, presence[i].pubkey.size,
                Py_False, Py_None);
            PyList_SetItem(ret, i, item);
        }
    }

    return ret;
}


// ----------------- Server interfaces --------------------

void server_delete(PyObject * self){
    s_server * s = (s_server *) PyCapsule_GetPointer(self, "dp5_server");
    if (s->regs) delete s->regs;
    if (s->lookups) delete s->lookups;
	PyMem_Free(s);
}

static PyObject* pygetnewserver(PyObject* self, PyObject* args) {
    PyObject *config_capsule;
    int ok = PyArg_ParseTuple(args, "O", &config_capsule);
    if (!ok)
        return NULL;
    DP5Config *config = getConfig(config_capsule);
    if (!config)
        return NULL;
    s_server * s = (s_server *) PyMem_Malloc(sizeof(s_server));
    if (!s)
        return NULL;
    s->regs = NULL;
    s->lookups = NULL;
    s->config = *config;

    PyObject * cap = PyCapsule_New((void *) s, "dp5_server",
        (PyCapsule_Destructor) &server_delete);
    return cap;
}

static PyObject* pyserverinitreg(PyObject* self, PyObject* args){
    PyObject * server_cap;
    unsigned int epoch;
    char * regdir;
    char * datadir;
    int ok = PyArg_ParseTuple(args, "OIss", &server_cap, &epoch, &regdir, &datadir);
    if (!ok) return NULL;
    if (!PyCapsule_CheckExact(server_cap)) return NULL;

    s_server * s = (s_server *) PyCapsule_GetPointer(server_cap, "dp5_server");
    // Clean delete of previous instance!
    if (s->regs) delete s->regs;

    s->regs = new DP5RegServer(s->config, epoch, regdir, datadir);
    Py_RETURN_NONE;
}

static PyObject* pyserverclientreg(PyObject* self, PyObject* args){
    PyObject * server_cap;
    Py_buffer data;

    int ok = PyArg_ParseTuple(args, "Os*", &server_cap, &data);
    if (!ok) {
        PyBuffer_Release(&data);
        return NULL;
    }
    if (!PyCapsule_CheckExact(server_cap)){
        PyBuffer_Release(&data);
        return NULL;
    }

    s_server * s = (s_server *) PyCapsule_GetPointer(server_cap, "dp5_server");
    // Clean delete of previous instance!
    if (!s->regs){
        PyBuffer_Release(&data);
        return NULL;
    }

    string datain;
    datain.assign((char*) data.buf, data.len);
    string dataout;

    Py_BEGIN_ALLOW_THREADS
    (s->regs)->client_reg(dataout, datain);
    Py_END_ALLOW_THREADS

    PyObject *ret = Py_BuildValue("z#", (char *)dataout.data(), dataout.length());
    PyBuffer_Release(&data);
    return ret;
}

static PyObject* pyserverepochchange(PyObject* self, PyObject* args){
    PyObject * server_cap;

    char * metafile;
    char * datafile;
    int ok = PyArg_ParseTuple(args, "Oss", &server_cap, &metafile, &datafile);
    if (!ok) return NULL;
    if (!PyCapsule_CheckExact(server_cap)) return NULL;

    s_server * s = (s_server *) PyCapsule_GetPointer(server_cap, "dp5_server");

    if (!s->regs) return NULL;

    ofstream md(metafile);
    ofstream d(datafile);
    unsigned int new_epoch = (s->regs)->epoch_change(md, d);
    d.close();
    md.close();

    return PyInt_FromLong(new_epoch);
}

static PyObject* pyserverinitlookup(PyObject* self, PyObject* args){
    PyObject * server_cap;
    unsigned int epoch;
    char * metafile;
    char * datafile;
    int ok = PyArg_ParseTuple(args, "OIss", &server_cap, &epoch, &metafile, &datafile);
    if (!ok) return NULL;
    if (!PyCapsule_CheckExact(server_cap)) return NULL;

    s_server * s = (s_server *) PyCapsule_GetPointer(server_cap, "dp5_server");
    // Clean delete of previous instance!
    if (s->lookups) delete s->lookups;

    s->lookups = new DP5LookupServer(metafile, datafile);
    // printf("meta: %s data: %s\n", metafile, datafile);

    Py_RETURN_NONE;
}

static PyObject* pyserverprocessrequest(PyObject* self, PyObject* args){
    PyObject * server_cap;
    Py_buffer data;

    int ok = PyArg_ParseTuple(args, "Os*", &server_cap, &data);
    if (!ok) {
         PyBuffer_Release(&data);
         return NULL;
    }
    if (!PyCapsule_CheckExact(server_cap)) {
         PyBuffer_Release(&data);
         return NULL;
    }

    s_server * s = (s_server *) PyCapsule_GetPointer(server_cap, "dp5_server");
    // Clean delete of previous instance!
    if (!s->lookups) return NULL;

    string datain;
    datain.assign((char*)data.buf, data.len);
    string dataout;

    Py_BEGIN_ALLOW_THREADS
    (s->lookups)->process_request(dataout, datain);
    Py_END_ALLOW_THREADS

    PyObject *ret = Py_BuildValue("z#", (char *)dataout.data(), dataout.length());
    PyBuffer_Release(&data);
    return ret;
}



// ------------------ Initialization of module ------------------------

static PyMethodDef dp5Methods[] =
{
     // Utilities
     {"make_config", pymake_config, METH_VARARGS, "Create a configuration object."},
     {"genkeypair", pygenkeypair, METH_VARARGS, "Generate a key pair."},
     {"getdatasize", pygetdatasize, METH_VARARGS, "Get plaintext size."},
     {"getepoch", pygetepoch, METH_VARARGS, "Get epoch."},

     // Client
     {"getnewclient", pygetnewclient, METH_VARARGS, "Initialize a new client"},
     {"clientregstart", pyclientregstart, METH_VARARGS, "Start client registration."},
     {"clientregcomplete", pyclientregcomplete, METH_VARARGS, "Complete client registration."},
     {"clientmetadatarequest", pyclientmetadatarequest, METH_VARARGS, "Metadata request"},
     {"clientmetadatareply", pyclientmetadatareply, METH_VARARGS, "Metadata reply"},
     {"clientlookuprequest", pyclientlookuprequest, METH_VARARGS, "Lookup request."},
     {"clientlookupreply", pyclientlookupreply, METH_VARARGS, "Lookup request."},

     // Server
     {"getnewserver", pygetnewserver, METH_VARARGS, "Get a new server instance."},
     {"serverinitreg", pyserverinitreg, METH_VARARGS, "Init registration server"},
     {"serverclientreg", pyserverclientreg, METH_VARARGS, "Process registration message"},
     {"serverepochchange", pyserverepochchange, METH_VARARGS, "Process a change of epoch"},
     {"serverinitlookup", pyserverinitlookup, METH_VARARGS, "Init lookup"},
     {"serverprocessrequest", pyserverprocessrequest, METH_VARARGS, "Process PIR request"},

     // No not delete null entry
     {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC

initdp5(void)
{
     (void) Py_InitModule("dp5", dp5Methods);
     printf("ZZ init\n");
     ZZ_p::init(to_ZZ(256));
     Pairing p; // initialize core
}

}
