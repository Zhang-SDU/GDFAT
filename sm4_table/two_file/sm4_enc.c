#include <stdlib.h>
#include <stdio.h>

#define u8 unsigned char
#define u32 unsigned long

typedef struct aes_wb_s {
	u32 T[32][4][256];
	u8  xor_table[32][48][16][16];
} *aes_wb_t;

void u32_to_u4(u32 in, u8* out)
{
	for (int i = 0; i < 8; i++)
	{
		out[i] = (in >> (28 - i * 4)) % 16;
	}
}

void u4_to_u32(u8* in, u32* out)
{
	*out = 0;
	for (int i = 0; i < 8; i++)
	{
		*out = ((u32)in[i] << (28 - i * 4)) ^ *out;
	}
}

void u32_to_u8(u32 in, u8* out)
{
	for (int i = 0; i < 4; i++)
	{
		out[i] = in >> (24 - i * 8);
	}
}

void u8_to_u32(u8* in, u32* out)
{
	*out = 0;
	for (int i = 0; i < 4; i++)
	{
		*out = ((u32)in[i] << (24 - i * 8)) ^ *out;
	}
}


int main(int argc, u8 *argv[]) 
{
	struct aes_wb_s aes;
	// reading the table
	FILE* f;
	f = fopen("table", "rb");
	fread(&aes, 1, sizeof(aes), f);
	fclose(f);

	u32 m[4] = { 0x7364755F, 0x6373745F, 0x7364755F, 0x6373745F };
	u32 X[36] = { 0 }; u32 c[4] = { 0 };
	printf("Enc_in:    ");
	u8 temp_m[4] = {0};
	u8 M[16] = {0};
	for (int i = 0; i < 4; i++)
	{
		u32_to_u8(m[i], temp_m);
		for (int j = 0; j < 4; j++)
		{
			M[4 * i + j] = temp_m[j];
		}
	}
	for (int i = 0; i < 16; i++)
	{
		printf("%02X ", M[i]);
	}
	printf("\n");
	for (int i = 0; i < 4; i++)
	{
		X[i] = m[i];
	}
	// Encryption process
	for (int round = 0; round < 32; round++)
	{
		u8 Xi0[8] = { 0 }; u8 Xi1[8] = { 0 }; u8 Xi2[8] = { 0 }; u8 Xi3[8] = { 0 };
		u32_to_u4(X[round], Xi0);
		u32_to_u4(X[round + 1], Xi1);
		u32_to_u4(X[round + 2], Xi2);
		u32_to_u4(X[round + 3], Xi3);
		u8 temp_list_u4[8] = { 0 };
		u32 temp = 0;
		for (int i = 0; i < 8; i++)
		{
			temp_list_u4[i] = aes.xor_table[round][i][Xi1[i]][Xi2[i]];
		}
		for (int i = 0; i < 8; i++)
		{
			temp_list_u4[i] = aes.xor_table[round][i + 8][temp_list_u4[i]][Xi3[i]];
		}
		u4_to_u32(temp_list_u4, &temp);
		u8 temp_list_u8[4] = { 0 };
		u32_to_u8(temp, temp_list_u8);

		u32 y0 = aes.T[round][0][temp_list_u8[0]];
		u32 y1 = aes.T[round][1][temp_list_u8[1]];
		u32 y2 = aes.T[round][2][temp_list_u8[2]];
		u32 y3 = aes.T[round][3][temp_list_u8[3]];
		u8 y0_u4[8] = { 0 }; u8 y1_u4[8] = { 0 }; u8 y2_u4[8] = { 0 }; u8 y3_u4[8] = { 0 };
		u32_to_u4(y0, y0_u4); u32_to_u4(y1, y1_u4); u32_to_u4(y2, y2_u4); u32_to_u4(y3, y3_u4);
		u8 temp_round_output1[8] = { 0 };
		u8 temp_round_output2[8] = { 0 };
		for (int i = 0; i < 8; i++)
		{
			temp_round_output1[i] = aes.xor_table[round][16 + i][y0_u4[i]][y1_u4[i]];
		}
		for (int i = 0; i < 8; i++)
		{
			temp_round_output2[i] = aes.xor_table[round][24 + i][y2_u4[i]][y3_u4[i]];
		}
		for (int i = 0; i < 8; i++)
		{
			temp_round_output1[i] = aes.xor_table[round][32 + i][temp_round_output1[i]][temp_round_output2[i]];
		}
		for(int i=0;i<8;i++)
		{
			temp_round_output1[i] = aes.xor_table[round][40 + i][temp_round_output1[i]][Xi0[i]];
		}
		u4_to_u32(temp_round_output1, &X[round + 4]);
	}

	for (int i = 0; i < 4; i++)
	{
		c[i] = X[35 - i];
	}

	printf("Enc_out:   ");
	u8 temp_c[4] = {0};
	u8 C[16] = {0};
	for (int i = 0; i < 4; i++)
	{
		u32_to_u8(c[i], temp_c);
		for (int j = 0; j < 4; j++)
		{
			C[4 * i + j] = temp_c[j];
		}
	}

	for (int i = 0; i < 16; i++)
	{
		printf("%02X ", C[i]);
	}
	printf("\n");
}
