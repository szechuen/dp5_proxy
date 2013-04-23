#include <Python.h>
#include "dp5params.h"
#include "dp5regclient.h"
#include "dp5lookupclient.h"

// Compilation notes 
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
};

static PyObject* say_hello(PyObject* self, PyObject* args)
{
    const char* name;
 
    if (!PyArg_ParseTuple(args, "s", &name))
        return NULL;
 
    printf("Hello %s!\n", name);
 
    Py_RETURN_NONE;   
}

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

void client_delete(PyObject * self){ 
    s_client * c = (s_client *) PyCapsule_GetPointer(self, "s_client");
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
    if (keysize != 32) return NULL;

    s_client * c = (s_client *) PyMem_Malloc(sizeof(s_client));
    memcpy(c->privkey, privkey, keysize);
    dp5.getpubkey(c->pubkey, c->privkey);
    c->cli = new DP5LookupClient(c->privkey);
    c->reg = new DP5RegClient(c->privkey);

    PyObject * cap = PyCapsule_New((void *) c, "s_client", 
        (PyCapsule_Destructor) &client_delete);

    return cap; 
}
 
static PyMethodDef HelloMethods[] =
{
     {"say_hello", say_hello, METH_VARARGS, "Greet somebody."},
     {"genkeypair", pygenkeypair, METH_VARARGS, "Generate a key pair."},
     {"getnewclient", pygetnewclient, METH_VARARGS, "Initialize a new client"},
     {NULL, NULL, 0, NULL}
};
 
PyMODINIT_FUNC
 
initdp5(void)
{
     (void) Py_InitModule("dp5", HelloMethods);
     ZZ_p::init(to_ZZ(256));
}

}
