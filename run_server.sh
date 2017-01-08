#!/bin/bash

if [ -n "$DP5_HOSTNAME" ] && [ -n "$DP5_EMAIL" ] && [ -n "$DP5_REGSVR" ]; then
    echo "INFO: Generating certificate..."

    if ! [ -d /etc/letsencrypt/live/"$DP5_HOSTNAME" ]; then
        if [ "$DP5_STAGING" == "true" ]; then
            letsencrypt certonly -n --standalone -d "$DP5_HOSTNAME" --agree-tos --email "$DP5_EMAIL" --staging
        else
            letsencrypt certonly -n --standalone -d "$DP5_HOSTNAME" --agree-tos --email "$DP5_EMAIL"
        fi
    else
        echo "INFO: Certificate already exists"
    fi

    if [ -d /etc/letsencrypt/live/"$DP5_HOSTNAME" ]; then
        echo "INFO: Starting server..."

        if ! [ -f /server.crt ]; then
            cp /etc/letsencrypt/live/"$DP5_HOSTNAME"/fullchain.pem /server.crt
            cp /etc/letsencrypt/live/"$DP5_HOSTNAME"/privkey.pem /server.key

            mkdir /regdir
            mkdir /datadir
            mkdir /logs

            envsubst < /server.cfg > /server.cfg
        fi

        python /dp5/dp5twistedserver.py server.cfg
    else
        echo "ERROR: Failed to generate certificate"
    fi
else
    echo "ERROR: Set DP5_HOSTNAME, DP5_EMAIL and DP5_REGSVR"
fi
