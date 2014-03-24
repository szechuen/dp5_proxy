#!/usr/bin/env python3

import sys
assert sys.version_info[0] == 3

import re

linefmt = re.compile("(\d+\.?\d*) -- ([a-f0-9]+) -- \[(\d+)\] ([^,]+), (.*)")

commands = {}
outputs = {}

with open(sys.argv[1]) as logfile:
    for line in logfile:
        m = re.match(linefmt, line)
        if not m:
            print("Can't match: "+ line, end='')

        (timestamp,client,tid,command,state) = m.groups()

        print("Time: {}, Client: {}, TID: {}, Command: {}, State: {}".format(
            timestamp,client,tid,command,state))

        if client+tid not in commands:
            commands[client+tid] = float(timestamp)
        else:
            print("Started at {}".format(commands[client+tid]))

        timeval = float(timestamp) - commands[client+tid]
        if state == "START":
            timeval = -timeval
            # reset start time
            commands[client+tid] = float(timestamp)
        elif state == "SEND" or state == "SEND00":
            timeval = -3 - timeval
        elif state == "SUCCESS":
            pass
        elif state == "FAIL":
            timeval = -7 - timeval
        else:
            continue
        if command not in outputs:
            fname = "{}-{}.log".format(sys.argv[1], command)
            outputs[command] = open(fname, 'w')
        print("{} {}".format(timestamp, timeval), file=outputs[command])

for f in outputs.values():
    f.close()

with open(sys.argv[1]+".gp", "w") as gp:
    print("plot 0 with lines, -3 with lines, -7 with lines, ", end='', file=gp)
    print(", ".join(["\"{0}-{1}.log\" with points title \"{1}\"".format(
        sys.argv[1], fname)for fname in outputs.keys()]), file=gp)


