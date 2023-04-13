#!/bin/bash

mkdir -p tmp
mount|grep -q $(pwd)/tmp || sudo mount -t tmpfs -o mode=01777,size=20m tmpfs tmp
cp attack_sm4.py ../sm4Fault.py ../sm4DA.py ../sm4_keyschedule tmp
cp ../sm4_bool/sm4_enc tmp
cd tmp
ulimit -c 0
./sm4_enc
mv sm4_enc sm4_enc.gold
./attack_sm4.py
