#!/usr/bin/env python3

import json
import sys

with open(sys.argv[1]) as config_file:
    config = json.load(config_file)

import os
if not os.path.exists(config["name"]):
    os.mkdir(config["name"])
os.chdir(config["name"])

server_base = {
    "server.ssl_module": "pyopenssl",
    "server.ssl_certificate": "testcerts/server.crt",
    "server.ssl_private_key": "testcerts/server.key"
}
client_config = {}


for servertype in ["standard", "combined"]:
    cur_config = config[servertype]
    port_base = 0xdb5
    if servertype == "combined":
        port_base += 0x20       # up to 31 lookup servers!
        cb = "CB"
    else:
        cb = ""

    base_config = {
            "epochLength": cur_config["epochLength"],
        "dataEncSize": servertype == "standard" and 80 or 32,
        "combined": servertype == "combined"
    }

    regserver_config = base_config
    regserver_config.update({
        "server": {
            "server.socket_host": cur_config["regserver"],
            "server.socket_port": port_base,
        },
        "isRegServer": True,
        "isLookupServer": False,
        "regdir": "store-reg"+cb+"/reg",
        "datadir": "store-reg" +cb+"/data",
    })

    regserver_config["server"].update(server_base)

    with open("regserver"+cb+".cfg", 'w') as regserver_file:
        json.dump(regserver_config, regserver_file)

    base_config.update({
        "regServer": "https://{}:{}".format(cur_config["regserver"],
            port_base)
        })

    for i in range(len(cur_config["lookupservers"])):
        name = cur_config["lookupservers"][i]
        lookupserver_config = base_config
        lookupserver_config.update({
            "server": {
                "server.socket_host": "0.0.0.0",
                "server.socket_port": port_base + i + 1,
            },
            "isRegServer": False,
            "isLookupServer": True,
            "datadir": "store-ls{}{}/data".format(cb, i),
        })
        lookupserver_config["server"].update(server_base)
        with open("lookupserver"+cb+"{}.cfg".format(i), 'w') as lookupserver_file:
            json.dump(lookupserver_config, lookupserver_file)

    client_config[servertype] = base_config
    client_config[servertype].update({
        "lookupServers": [ "{}:{}".format(
            cur_config["lookupservers"][i], port_base+1+i)
            for i in range(len(cur_config["lookupservers"]))],
        "privacyLevel": len(cur_config["lookupservers"])-1,
	"regServer": "{}:{}".format(cur_config["regserver"], port_base)
    })

with open('client.cfg', 'w') as client_file:
    json.dump(client_config, client_file)

with open('fabfile.py', 'w') as fab_file, \
    open("../fabfile.py") as fab_file_source:
    for l in fab_file_source:
        fab_file.write(l)

    code = """
env.roledefs = {{
    "regserver" : {!r},
    "lookupservers": {!r},
    "regserverCB" : {!r},
    "lookupserversCB": {!r},
    "client": [ {!r} ]
}}

# unique servers
env.roledefs["servers"] = list({{ s for v in env.roledefs.values() for s in v }})

"""
    fab_file.write(code.format(
        [ config["standard"]["regserver"] ],
        config["standard"]["lookupservers"],
        [ config["combined"]["regserver"] ],
        config["combined"]["lookupservers"],
	config["client"]))

with open('servers', 'w') as server_list:
    for comb, cb in [("standard", ""), ("combined", "CB")]:
        print(config[comb]["regserver"], "regserver" + cb + ".cfg", file=server_list)
        for i in range(len(config[comb]["lookupservers"])):
            print(config[comb]["lookupservers"][i], "lookupserver{0}{1}.cfg".format(cb, i),
                file=server_list)
