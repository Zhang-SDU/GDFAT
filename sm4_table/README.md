Usage
-----

Here are two versions based on chow table but only internal encodings.

One file version
---------------------

```sm4_table_generator.c``` is the generator code to generate table.  
```sm4_enc``` is using the generated tables by ```include``` to encrypt any plaintext.  

```bash
gcc -o nosuchcon_2013_whitebox_allenc_generator nosuchcon_2013_whitebox_allenc_generator.c
gcc -o nosuchcon_2013_whitebox_allenc nosuchcon_2013_whitebox_allenc.c
./nosuchcon_2013_whitebox_allenc_generator
./nosuchcon_2013_whitebox_allenc $(echo testtesttesttest|xxd -p)
Input:    74 65 73 74 74 65 73 74 74 65 73 74 74 65 73 74 
Enc in:   B2 B2 B2 B2 68 68 68 68 51 51 51 51 B2 B2 B2 B2 
Enc out:  57 65 7A 27 70 2C 07 05 DA 7D 12 B2 0C 63 0F CE 
Output:   4C 74 7B 5C 53 54 DB 2B 6D 13 39 C9 31 81 33 40 
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
Input:    74 65 73 74 74 65 73 74 74 65 73 74 74 65 73 74 
Enc in:   74 74 74 74 65 65 65 65 73 73 73 73 74 74 74 74 
Enc out:  4C 74 7B 5C 53 54 DB 2B 6D 13 39 C9 31 81 33 40 
Output:   4C 74 7B 5C 53 54 DB 2B 6D 13 39 C9 31 81 33 40 
```
