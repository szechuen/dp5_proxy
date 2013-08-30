Running the servers
===================

Configuration
------------- 

1. Set up a registration server.

	Create a file `regserver.cfg` (JSON) that is modeled after the following:

			{
				"server" : {	/* configuration values passed to cherrypy web server */
					"server.socket_host": "0.0.0.0", 	/* bind to all IP interfaces */
					"server.socket_port": 8443,			/* listen on port 8443 */
					/* These are needed to support SSL; leave them out to use plain HTTP */
					"server.ssl_module": "pyopenssl",
					"server.ssl_certificate": "testcerts/server.crt",
					"server.ssl_private_key": "testcerts/server.key"
				},
				"isRegServer": true,
				"isLookupServer": false, 	/* set to true if you want this to also be a lookup server */
				"regdir": "regdir", 		/* directory for storing registrations for next epoch */
				"datadir": "datadir"		/* directory for storing presence database */ 
			}                                                                            
			
    You will also need to create empty directories `regdir/` and `datadir/`. If you are using SSL, you will need to generate a server key and obtain a certificate. (Could be self-signed.)

	To run the registration server, execute:
	
			python dp5server.py regserver.cfg
			
2. Set up one or more lookup servers.

	For each server, create a file `lookupserver.cfg` (JSON) similar to the following:

			{
				"server" : {	/* configuration values passed to cherrypy web server */
					"server.socket_host": "0.0.0.0", 	/* bind to all IP interfaces */
					"server.socket_port": 8444,			/* listen on port 8444 */									
					/* These are needed to support SSL; leave them out to use plain HTTP */
					"server.ssl_module": "pyopenssl",
					"server.ssl_certificate": "testcerts/server.crt",
					"server.ssl_private_key": "testcerts/server.key"
				},
				"isRegServer": false,		
				"isLookupServer": true,
				"regServer": "https://localhost:8443", 	/* address of the registration server */
				"datadir": "lookupdatadir/"			/* directory for storing presence database */ 
			}                                   
			
    Once again, you will need to create a data directory (`lookupdatadir/` in this case) and obtain a server certificate. The lookup servers need to be able to find the registration server to download the presence database. Start the servers by running:

			python dp5server.py lookupserver.cfg
			
Running the Test Harness
========================

Generating Users
----------------

The `users.py` script will generate a set of users and their buddies:

		python users.py 200 users.200
		
This will generate a database of 200 users and store it in a file users.200. Each user will be assigned up to MAX_BUDDIES (100) buddies at random.

Configuring the Client
----------------------

The client configuration is stored in JSON, see `servers.cfg` for an example:

		{
			"regServer": "localhost:8443",  /* address of the registration server */
			"lookupServers":               	/* addresses of the lookup servers */            
					[ "localhost:8444", "localhost:8445" ], 
			"privacyLevel": 1				/* maximum number servers that can collude */
		}
		
The privacy level must be at most one less than the number of available lookup servers.

Running the Client
------------------           

			python dp5client.py servers.cfg users.200
			
This will proceed to register each user in the `users.200` file, then use a debugging command to advance the registration to the server, and then have each client look up all of its buddies using the lookup servers.

Caveats
-------

The client will use a number of processes for querying (default: 5*number of CPUs) so this may add extra load on your machine. 

There is an interaction between the process pool on the client, the thread pool on the lookup server, and the `urllib3` module that keeps connections open that can cause the lookup server to wait for a request on an idle connection while not servicing requests on other connections and get "stuck". You will notice that nothing is happening for about 10 seconds and then things move forward a bit. The simplest way to fix it is to increase the size of the cherrypy threadpool to match the number of client processes: add `"server.thread_pool": 100` to the `"server"` section of `lookupserver.cfg`. We are working on a better longer-term solution.