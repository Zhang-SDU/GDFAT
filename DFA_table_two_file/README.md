Usage
-----

Faulting multiple times the tables requires many disk writes so we'll do it in a tmpfs.  
All steps are performed by ```attack.sh```:

```bash
#!/bin/bash

mkdir -p tmp
mount|grep -q $(pwd)/tmp || sudo mount -t tmpfs -o mode=01777,size=20m tmpfs tmp
cp attack_sm4.py ../sm4Fault.py ../sm4DA.py ../sm4_keyschedule tmp
cp ../sm4_table/two_file/sm4_table_generator.c ../sm4_table/two_file/sm4_enc.c ../sm4_table/two_file/sm4.h tmp
cd tmp
ulimit -c 0
gcc -o sm4_table_generator sm4_table_generator.c
./sm4_table_generator
gcc -o sm4_enc sm4_enc.c
./sm4_enc
mv table table_gold
./attack_sm4.py
```

Adapt it to your setup if needed. 

It requires ```sm4Fault.py``` and ```sm4DA.py``` from this repository.

