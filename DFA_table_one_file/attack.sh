#!/bin/bash

mkdir -p tmp
mount|grep -q $(pwd)/tmp || sudo mount -t tmpfs -o mode=01777,size=20m tmpfs tmp
cp attack_sm4.py ../sm4Fault.py ../sm4DA.py ../sm4_keyschedule tmp
cp ../sm4_table/one_file/sm4_enc tmp
cd tmp
./sm4_enc
ulimit -c 0
cp -a sm4_enc sm4_enc.gold
./attack_sm4.py
