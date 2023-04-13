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
gcc -O3 sm4_bool.c sm4_enc.c -o sm4_enc

# gcc -O3 sm4_linear_bool2.c sm4_enc.c -o sm4_enc

# gcc -O3 sm4_linear_bool3.c sm4_enc.c -o sm4_enc

# gcc -O3 sm4_nolinear_bool.c sm4_enc.c -o sm4_enc 
```
