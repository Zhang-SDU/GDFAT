Usage
-----

Here are two versions based on chow table but only internal encodings.

One file version
---------------------

```sm4_table_generator.c``` is the generator code to generate table.  
```sm4_enc``` is using the generated tables by ```include``` to encrypt any plaintext.  

```bash
gcc -o sm4_table_generator sm4_table_generator.c
./sm4_table_generator 
gcc -o sm4_enc sm4_enc.c
./sm4_enc
Enc_in:    73 64 75 5F 63 73 74 5F 73 64 75 5F 63 73 74 5F
Enc_out:   52 F5 0C B1 FE A7 1A B9 6F 4E E7 DF 49 F8 5F C8
```

Two file version
-------------------------------

```sm4_table_generator.c``` is the generator code to generate table.  
```sm4_enc``` is using the generated tables by ```fopen and fread ``` to encrypt any plaintext. 

```bash
gcc -o nosuchcon_2013_whitebox_noextenc_generator nosuchcon_2013_whitebox_noextenc_generator.c
gcc -o nosuchcon_2013_whitebox_noextenc nosuchcon_2013_whitebox_noextenc.c
./nosuchcon_2013_whitebox_noextenc_generator
./nosuchcon_2013_whitebox_noextenc $(echo testtesttesttest|xxd -p)
Enc_in:    73 64 75 5F 63 73 74 5F 73 64 75 5F 63 73 74 5F
Enc_out:   52 F5 0C B1 FE A7 1A B9 6F 4E E7 DF 49 F8 5F C8 
```