#include <stdio.h>
#include <stdlib.h>
#include<time.h>
extern void AES_128_encrypt(unsigned char *ciphertext, unsigned char *plaintext);

#define u8 unsigned char
#define u32 unsigned long


void u32_to_u8(u32 in, u8* out)
{
	for (int i = 0; i < 4; i++)
	{
		out[i] = in >> (24 - i * 8);
	}
}

const int BLOCK_SIZE = 16;

int main(int argc, char **argv)
{
  unsigned char input[BLOCK_SIZE];
  unsigned char out[BLOCK_SIZE];

  u32 m[4] = { 0x7364755F, 0x6373745F, 0x7364755F, 0x6373745F };
  u8 temp_m[4] = {0};

  for (int i = 0; i < 4; i++)
	{
		u32_to_u8(m[i], temp_m);
		for (int j = 0; j < 4; j++)
		{
			input[4 * i + j] = temp_m[j];
		}
	}

  clock_t st = clock();

  // Encryption
    AES_128_encrypt(out, input);
  clock_t et = clock();
  printf("Enc_in:    ");
  for(int i = 0;i<16;++i) {
    printf("%02x ",input[i]);
  }
  printf("\n");
  printf("Enc_out:   ");
  for (int i = 0; i < BLOCK_SIZE; i++) {
    printf("%02x ", out[i]);
  }
  printf("\n");

  return 0;
}
