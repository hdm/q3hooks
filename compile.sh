#!/bin/bash

MOD=hooks
gcc -Wall -shared -Wl,-soname,$MOD.so.1 -o $MOD.so $MOD.c -ldl

