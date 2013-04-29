#include <Python.h>
#include "dp5params.h"

#include "dp5regclient.h"
#include "dp5lookupclient.h"

#include "dp5regserver.h"
#include "dp5lookupserver.h"

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
    unsigned char privkey[DP5Params::PRIVKEY_BYTES];
    unsigned char pubkey[DP5Params::PUBKEY_BYTES];
    DP5RegClient * reg;
    DP5LookupClient * cli;
    DP5LookupClient::Request req;
};

struct s_server {
    DP5RegServer * regs;
    DP5LookupServer * lookups;    
};


// ------------------------- Util & Crypto interfaces ----------

static PyObject* pygenkeypair(PyObject* self, PyObject* args){

    DP5Params dp5;
    unsigned char privkey[DP5Params::PRIVKEY_BYTES];
    unsigned char pubkey[DP5Params::PUBKEY_BYTES];
    dp5.genkeypair(pubkey, privkey);

    PyObject *ret = Py_BuildValue("(z#z#)", 
                        (char *)pubkey, DP5Params::PUBKEY_BYTES,
                        (char *)privkey, DP5Params::PRIVKEY_BYTES ); 

    return ret;
} 

static PyObject* pygetdatasize(PyObject* self, PyObject* args){
    return PyInt_FromLong(DP5Params::DATAPLAIN_BYTES);
}

static PyObject* pygetepoch(PyObject* self, PyObject* args){
    return PyInt_FromLong(DP5Params::current_epoch());
}


// ---------------------- Client interfaces -------------------------

void client_delete(PyObject * self){ 
    s_client * c = (s_client *) PyCapsule_GetPointer(self, "dp5_client");
    delete c->cli;
    delete c->reg;
    PyMem_Free(c);
}

static PyObject* pygetnewclient(PyObject* self, PyObject* args){

    // Get a private key
    char *privkey;
    Py_ssize_t keysize;
    DP5Params dp5;

    int ok = PyArg_ParseTuple(args, "z#", &privkey, &keysize);
    if (!ok || keysize != 32) return NULL;

    s_client * c = (s_client *) PyMem_Malloc(sizeof(s_client));
    memcpy(c->privkey, privkey, keysize);
    dp5.getpubkey(c->pubkey, c->privkey);
    c->cli = new DP5LookupClient(c->privkey);
    c->reg = new DP5RegClient(c->privkey);

    // Allocate a request in place
    DP5LookupClient::Request * temp = new (&(c->req)) DP5LookupClient::Request();

    PyObject * cap = PyCapsule_New((void *) c, "dp5_client", 
        (PyCapsule_Destructor) &client_delete);

    return cap; 
}

static PyObject* pyclientregstart(PyObject* self, PyObject* args){
    // We expect 2 arguments: an s_client and a buddy list
    PyObject* sclient;
    PyObject* buddielist;
    int ok = PyArg_ParseTuple(args, "OO", &sclient, &buddielist);
    if (!ok) return NULL;
    if (!PyCapsule_CheckExact(sclient)) return NULL;
    if (!PyList_Check(buddielist)) return NULL;

    string result;
    vector<BuddyInfo> bs;

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
        
        if (PyString_Size(pubk) != DP5Params::PUBKEY_BYTES || 
                PyString_Size(data) != DP5Params::DATAPLAIN_BYTES){   
            PyObject_Print(item, stdout, 0);
            PyErr_SetString(PyExc_RuntimeError, "Bad item format");
            return NULL;  }

        BuddyInfo b;
        memmove(b.pubkey, PyString_AsString(pubk), DP5Params::PUBKEY_BYTES);
        memmove(b.data, PyString_AsString(data), DP5Params::DATAPLAIN_BYTES);
        bs.push_back(b);
    }

    s_client * c = (s_client *) PyCapsule_GetPointer(sclient, "dp5_client");
    if (!c){
         PyErr_SetString(PyExc_RuntimeError, "Bad capsule");
         return NULL;
    }
    ok = (c->reg)->start_reg(result, bs);
    if (ok != 0x00){
        printf("Error: %hd\n",ok);
        PyErr_SetString(PyExc_RuntimeError, "Protocol interface error");
        return NULL;
    }    
    PyObject *ret = Py_BuildValue("z#", 
                        (char *)result.data(), result.length()); 
    return ret;
}

static PyObject* pyclientregcomplete(PyObject* self, PyObject* args){
    PyObject* sclient;
    char *msg;
    Py_ssize_t msgsize;
    int ok = PyArg_ParseTuple(args, "Oz#", &sclient, &msg, &msgsize);
    if (!ok) return NULL;
    if (!PyCapsule_CheckExact(sclient)) return NULL;
    
    string smsg;
    smsg.assign(msg, msgsize);

    s_client * c = (s_client *) PyCapsule_GetPointer(sclient, "dp5_client");
    if (!c){
         PyErr_SetString(PyExc_RuntimeError, "Bad capsule");
         return NULL;
    }
    ok = (c->reg)->complete_reg(smsg);
    if (ok != 0x00){
        printf("Error: %hd\n",ok);
        PyErr_SetString(PyExc_RuntimeError, "Protocol interface error");
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject* pyclientmetadatarequest(PyObject* self, PyObject* args){
    PyObject* sclient;
    unsigned int epoch;

    int ok = PyArg_ParseTuple(args, "Ok", &sclient, &epoch);
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
    Py_ssize_t datasize;

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
        printf("Error: %hd\n",ok);
        PyErr_SetString(PyExc_RuntimeError, "Protocol interface error");
        return NULL; }

    Py_RETURN_NONE;
}

static PyObject* pyclientlookuprequest(PyObject* self, PyObject* args){
    // printf("Got to request... 1\n");
    PyObject* sclient;
    PyObject* buddies;
    int ok = PyArg_ParseTuple(args, "OO", &sclient, &buddies);
    if (!ok) return NULL;
    if (!PyCapsule_CheckExact(sclient)) return NULL;
    if (!PyList_Check(buddies)) return NULL;

    s_client * c = (s_client *) PyCapsule_GetPointer(sclient, "dp5_client");
    if (!c){
         PyErr_SetString(PyExc_RuntimeError, "Bad capsule");
         return NULL;
    }

    vector<BuddyKey> buds;
    for(unsigned int i = 0; i < PyList_Size(buddies); i++)
    {
        PyObject * item = PyList_GetItem(buddies, i);
        if (!item || !PyString_Check(item) 
                || PyString_Size(item) != DP5Params::PUBKEY_BYTES) {
            PyErr_SetString(PyExc_RuntimeError, "Item is null or not a string or not the right length");
            return NULL; }

        BuddyKey b;
        memmove(b.pubkey, PyString_AsString(item), DP5Params::PUBKEY_BYTES);
        buds.push_back(b);
    }

    const unsigned int num_servers = (c->cli)->NUM_PIRSERVERS;
    if (!(c->cli)) return NULL;

    ok = (c->cli)->lookup_request(c->req, buds, num_servers, num_servers-1);
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

    vector<BuddyPresence> presence;
    ok = (c->req).lookup_reply(presence, msgStoCpir);
    if (ok != 0x00) {
        printf("Error: %hd\n",ok);
        PyErr_SetString(PyExc_RuntimeError, "Protocol interface error");
        return NULL; }
    
    PyObject* ret = PyList_New(presence.size());
    for( unsigned int i = 0; i < presence.size(); i++){
        if (presence[i].is_online) {
            PyObject * item = Py_BuildValue("z#Oz#", presence[i].pubkey, 
                DP5Params::PUBKEY_BYTES, Py_True, 
                presence[i].data, DP5Params::DATAPLAIN_BYTES);
            PyList_SetItem(ret, i, item); }
        else {
            PyObject * item = Py_BuildValue("z#OO", presence[i].pubkey, 
                DP5Params::PUBKEY_BYTES, Py_False, Py_None);
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

static PyObject* pygetnewserver(PyObject* self, PyObject* args){
    s_server * s = (s_server *) PyMem_Malloc(sizeof(s_server));
    s->regs = NULL;
    s->lookups = NULL;
    
    PyObject * cap = PyCapsule_New((void *) s, "dp5_server", 
        (PyCapsule_Destructor) &server_delete);
    return cap;
}

static PyObject* pyserverinitreg(PyObject* self, PyObject* args){
    PyObject * server_cap;
    unsigned int epoch;
    char * regdir;
    char * datadir;
    int ok = PyArg_ParseTuple(args, "Okss", &server_cap, &epoch, &regdir, &datadir);
    if (!ok) return NULL;
    if (!PyCapsule_CheckExact(server_cap)) return NULL;

    s_server * s = (s_server *) PyCapsule_GetPointer(server_cap, "dp5_server");
    // Clean delete of previous instance!
    if (s->regs) delete s->regs;

    s->regs = new DP5RegServer(epoch, regdir, datadir);
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
    int ok = PyArg_ParseTuple(args, "Okss", &server_cap, &epoch, &metafile, &datafile);
    if (!ok) return NULL;
    if (!PyCapsule_CheckExact(server_cap)) return NULL;

    s_server * s = (s_server *) PyCapsule_GetPointer(server_cap, "dp5_server");
    // Clean delete of previous instance!
    if (s->lookups) delete s->lookups;

    s->lookups = new DP5LookupServer();
    // printf("meta: %s data: %s\n", metafile, datafile);
    (s->lookups)->init(epoch, metafile, datafile);

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
}

}
