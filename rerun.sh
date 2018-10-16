#!/bin/bash
sudo fuser -k 23/tcp
sudo ./dropbear -p 23 -T 3 && \
./dbclient localhost -p 23 -A

