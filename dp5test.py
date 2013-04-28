import random
import dp5

## Generate a curve25519 key pair
pubk,privk = dp5.genkeypair()
assert len(pubk) == 32 and len(privk) == 32

## The data size is currently an AES block in length
assert dp5.getdatasize() == 16 

## Initialize a registration server
server = dp5.getnewserver()
epoch = dp5.getepoch() ## You can read the current epoch
dp5.serverinitreg(server, epoch, "regdir", "datadir")

## Make NUM random clients with friend lists
## with about 2*FRI friends each
NUM = 100
FRI = 2
xkeys = {}
xklookup = {}
online = {}
friends = dict([(i, set([])) for i in range(NUM)])
clients = {}
for i in range(NUM):
    xkeys[i] = dp5.genkeypair()
    xklookup[xkeys[i][0]] = i
    online[i] = random.choice([True, False, False, False])
    
    fs = random.sample(range(NUM), FRI)
    for f in fs:
        friends[i].add(f)
        friends[f].add(i)

for i in range(NUM):
    print ".",
    pubk,privk = xkeys[i]

    ## Make up some friends
    buddies = []
    for f in friends[i]:
        pub, _ = xkeys[f]
        assert len(pub) == 32
        data = ("F%s" % i).center(dp5.getdatasize(), "-")
        buddies += [(pub,data)]

    ## Register a new client instance
    client = dp5.getnewclient(privk)
    clients[i] = client

    if not online[i]:
        continue

    ## Get the registration message for a list of friends [(pubkey(32), data(16))]
    reg_msg = dp5.clientregstart(client, buddies);
    assert  len(reg_msg) == 2604

    # Send message to server.
    reply_msg = dp5.serverclientreg(server, reg_msg)

    # Process the message back from the server
    dp5.clientregcomplete(client, reply_msg)

## Roll over the epoch
newepoch = dp5.serverepochchange(server, "meta%d.dat" % epoch, 
                                         "data%d.dat" % epoch)
assert epoch + 1 == newepoch

## Now create a set of servers
epoch = epoch + 1
servers = []
for _ in range(5):
    s = dp5.getnewserver()
    dp5.serverinitlookup(s, epoch, "meta%d.dat" % (epoch-1), 
                                         "data%d.dat" % (epoch-1))
    servers += [s]

## First make all request metadata & presence
for i in range(NUM):
    metamsg = dp5.clientmetadatarequest( clients[i], epoch)
    metareply = dp5.serverprocessrequest(servers[0], metamsg)
    dp5.clientmetadatareply(clients[i], metareply)

    buddies = [xkeys[f][0] for f in friends[i]]
    reqs = dp5.clientlookuprequest(clients[i], buddies)
    assert len(reqs) == 5

    replies = []
    for k in range(len(reqs)):
        m = reqs[k]
        if m != None:
            replies += [dp5.serverprocessrequest(servers[k], reqs[k])]  
        else:
            replies += [None]          

    presence = dp5.clientlookupreply(clients[i], replies)
    for (kx,px,dx) in presence:
        assert online[xklookup[kx]] == px            

