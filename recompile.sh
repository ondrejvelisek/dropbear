#!/bin/bash
make clean
autoconf && \
autoheader && \
./configure && \
make

