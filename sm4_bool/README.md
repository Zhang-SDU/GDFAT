Usage
-----

Here are four versions based on boolean circuit.

sm4_bool.c version
---------------------

This is an ordinary Boolean circuit implementation without any masking.    


sm4_linear_bool2.c version
-------------------------------

This is a Boolean circuit implementation of a second-order linear mask.    


sm4_linear_bool3.c version
-------------------------------

This is a Boolean circuit implementation of a third-order linear mask.    


sm4_nolinear_bool.c version
-------------------------------

This is a Boolean circuit implementation of a nonlinear mask.    


```sm4_enc.c``` is a program that can encrypt any plaintest using any of the above four Boolean circuits.

```bash
gcc sm4_table_generator.c -o sm4_table_generator
./sm4_table_generator
gcc sm4_enc.c -o sm4_enc
./sm4_enc

Enc_in:    73 64 75 5F 63 73 74 5F 73 64 75 5F 63 73 74 5F
Enc_out:   52 F5 0C B1 FE A7 1A B9 6F 4E E7 DF 49 F8 5F C8 
```
