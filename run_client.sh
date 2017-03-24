#!/bin/bash

echo "INFO: Starting tor..."

tor &

echo "INFO: Starting dp5_proxy..."

/dp5_proxy/dp5_proxy
