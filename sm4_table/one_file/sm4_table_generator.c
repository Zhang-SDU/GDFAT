#include "sm4.h"
#include<time.h>

// All tables used in encryption
typedef struct aes_wb_s {
	u32 T[32][4][256];
	u8  xor_table[32][48][16][16];
} *aes_wb_t;

struct aes_wb_s aes;


// The Seed Key
u32 MK[4] = { 0x4D795365, 0x63726574, 0x4B657921, 0x32303232 };

// The Key List
u32 Key_List[36] = { 0 };

// Store all internal codes in the function
u8 sm4_code[32][80][16] = { 0 };
u8 sm4_inverse_code[32][80][16] = { 0 };

// Internal code for storing intermediate states
u8 x_code[8][8][16] = { 0 };
u8 x_inverse_code[8][8][16] = { 0 };

// Randomly generate a 4 * 4 internal code (4 bit S-box)
void random_code(u8* code, u8* inverse_code, bool tag)
{
	if (tag)
	{
		u8 key = rand() % 0x10;
		for (int round = 0; round < 10; round++)
		{
			for (int i = 0; i < 16; i++)
			{
				code[i] = (Coding_SBOX[i] ^ key) % 0x10;
			}
		}
		for (int i = 0; i < 16; i++)
		{
			inverse_code[code[i]] = i;
		}
	}
	else
	{
		for (int i = 0; i < 16; i++)
		{
			code[i] = i;
			inverse_code[i] = i;
		}
	}
}

// Quadruple byte u8 to u32 conversion
void u8_to_u32(u8* in, u32* out)
{
	*out = 0;
	for (int i = 0; i < 4; i++)
	{
		*out = ((u32)in[i] << (24 - i * 8)) ^ *out;
	}
}

// u32 to quad byte u8 conversion
void u32_to_u8(u32 in, u8* out)
{
	for (int i = 0; i < 4; i++)
	{
		out[i] = in >> (24 - i * 8);
	}
}

// u32 conversion to 8 half bytes
void u32_to_u4(u32 in, u8* out)
{
	for (int i = 0; i < 8; i++)
	{
		out[i] = (in >> (28 - i * 4)) % 16;
	}
}

// 8 half bytes converted to u32
void u4_to_u32(u8* in, u32* out)
{
	*out = 0;
	for (int i = 0; i < 8; i++)
	{
		*out = ((u32)in[i] << (28 - i * 4)) ^ *out;
	}
}

// 1 byte converted to 2 half bytes
void u8_to_u4(u8 in, u8* out)
{
	for (int i = 0; i < 2; i++)
	{
		out[i] = (in >> (4 - i * 4)) % 0x10;
	}
}

// 2 half bytes converted to 1 byte
void u4_to_u8(u8* in, u8* out)
{
	*out = 0;
	for (int i = 0; i < 2; i++)
	{
		*out = (in[i] << (4 - i * 4)) ^ *out;
	}
}

// 4bit Iso-or
u8 xor_u4(u8 x1, u8 x2)
{
	u8 result = (x1 ^ x2) % 16;
	return result;
}

// T' function in the key generation algorithm
u32 func_T1(u32 input)
{
	u8 SboxValueList[4] = { 0 };
	u32 SBoxValue = 0;
	u32 LValue = 0;
	u32_to_u8(input, SboxValueList);
	for (int i = 0; i < 4; i++)
	{
		SboxValueList[i] = TBL_SBOX[SboxValueList[i]];
	}
	u8_to_u32(SboxValueList, &SBoxValue);
	LValue = SBoxValue ^ left_move(SBoxValue, 13) ^ left_move(SBoxValue, 23);
	return LValue;
}

// Sbox in encryption algorithm
u32 func_Enc_Sbox(u32 input)
{
	u8 SboxValueList[4] = { 0 };
	u32 SboxValue = 0;
	u32_to_u8(input, SboxValueList);
	for (int i = 0; i < 4; i++)
	{
		SboxValueList[i] = TBL_SBOX[SboxValueList[i]];
	}
	u8_to_u32(SboxValueList, &SboxValue);
	return SboxValue;
}

// L-transform in encryption algorithm ----- matrix multiplication implementation
u32 func_Enc_L(u32 SboxValue)
{
	u8 SboxValueList[4] = { 0 };
	u32_to_u8(SboxValue, SboxValueList);
	u8 L_value_list[4] = { 0 };
	u8 y0[4] = { 0 }; u8 y1[4] = { 0 }; u8 y2[4] = { 0 }; u8 y3[4] = { 0 };

	// Four 8-input and 32-output tables with code before and after
	cal_y0(SboxValueList[0], y0);
	cal_y1(SboxValueList[1], y1);
	cal_y2(SboxValueList[2], y2);
	cal_y3(SboxValueList[3], y3);

	for (int i = 0; i < 4; i++)
	{
		L_value_list[i] = y0[i] ^ y1[i] ^ y2[i] ^ y3[i];
	}
	u32 L_value = 0;
	u8_to_u32(L_value_list, &L_value);
	return L_value;
}

// Key_Schedule algorithm
void Key_Schedule(u32* Key_List, u32* MK)
{
	for (int i = 0; i < 4; i++)
	{
		Key_List[i] = MK[i] ^ TBL_SYS_PARAMS_FK[i];
	}
	for (int i = 0; i < 32; i++)
	{
		Key_List[i + 4] = Key_List[i] ^ func_T1(Key_List[i + 1] ^ Key_List[i + 2] ^ Key_List[i + 3] ^ TBL_FIX_PARAMS_CK[i]);
	}
}

// Generate all internal codes
void generate_inter_code()
{
	for (int i = 0; i < 8; i++)
	{
		for (int j = 0; j < 8; j++)
		{
			random_code(x_code[i][j], x_inverse_code[i][j], false);
		}
	}
	for (int i = 0; i < 32; i++)
	{
		for (int j = 0; j < 80; j++)
		{
			random_code(sm4_code[i][j], sm4_inverse_code[i][j], true);
		}
	}
}

// Generate 8-in/4-out xor table (with code)
void generator_xor_table(aes_wb_t aes, int round, int index, u8* decode1, u8* decode2, u8* encode)
{
	for (int i = 0; i < 0x10; i++)
	{
		u8 temp1 = decode1[i];
		for (int j = 0; j < 0x10; j++)
		{
			u8 temp2 = decode2[j];
			aes->xor_table[round][index][i][j] = encode[(temp1 ^ temp2) % 0x10];
		}
	}
}
// Generate a T-table (8 in 32 out)
void generate_one_T_table(aes_wb_t aes, int round, int index, u8 rk, int decode_start, int encode_start)
{
	for (int i = 0; i < 256; i++)
	{
		u8 i_list[2] = { 0 };
		// Split into two half bytes
		u8_to_u4(i, i_list);
		// Decode the two half bytes separately
		i_list[0] = sm4_inverse_code[round][decode_start][i_list[0]];
		i_list[1] = sm4_inverse_code[round][decode_start + 1][i_list[1]];
		// Compose a byte
		u8 temp_i = 0;
		u4_to_u8(i_list, &temp_i);
		// Lookup table
		temp_i = temp_i ^ rk;
		u8 Sbox_Value = TBL_SBOX[temp_i];
		u8 y[4] = { 0 };
		if (index == 0)
		{
			cal_y0(Sbox_Value, y);
		}
		else if (index == 1)
		{
			cal_y1(Sbox_Value, y);
		}
		else if (index == 2)
		{
			cal_y2(Sbox_Value, y);
		}
		else
		{
			cal_y3(Sbox_Value, y);
		}
		// Convert to Eight 4bit
		u32 L_value = 0;
		u8 L_value_list[8] = { 0 };
		u8_to_u32(y, &L_value);
		u32_to_u4(L_value, L_value_list);
		// Eight 4bit overcodes
		for (int i = 0; i < 8; i++)
		{
			L_value_list[i] = sm4_code[round][encode_start + i][L_value_list[i]];
		}
		// Eight 4bit numbers combined
		u4_to_u32(L_value_list, &L_value);
		aes->T[round][index][i] = L_value;
	}
}

// Generate four 8-input and 32-output tables
void generate_four_T_table(aes_wb_t aes, int round, int decode_start, int encode_start)
{
	u8 rk[4] = { 0 };
	u32_to_u8(Key_List[round + 4], rk);
	for (int i = 0; i < 4; i++)
	{
		generate_one_T_table(aes, round, i, rk[i], decode_start + i * 2, encode_start + i * 8);
	}
}

// Generate tables by round:48 xor tables + Four 8-in 32-out T-tables
void generate_one_whole_table(aes_wb_t aes)
{
	int round = 0;
	// Record the index of the xor table
	int num = 0; 
	// Eight xor table   x1 ^ x2
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, x_inverse_code[1][i], x_inverse_code[2][i], sm4_code[round][i]);
	}
	// Eight xor table   (x1 ^ x2) ^ x3
	num = 8;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][i], x_inverse_code[3][i], sm4_code[round][i + 8]);
	}
	num = 16;
	// Four 8-input and 32-output meters
	generate_four_T_table(aes, round, 8, 16);
	// y0 ^ y1
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][16 + i], sm4_inverse_code[round][24 + i], sm4_code[round][48 + i]);
	}
	num = 24;
	// y2 ^ y3
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][32 + i], sm4_inverse_code[round][40 + i], sm4_code[round][56 + i]);
	}
	num = 32;
	// (y0 ^ y1) ^ (y2 ^ y3)
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][48 + i], sm4_inverse_code[round][56 + i], sm4_code[round][64 + i]);
	}
	num = 40;
	// (y0 ^ y1 ^ y2 ^ y3) ^ x0
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][64 + i], x_inverse_code[0][i], sm4_code[round][72 + i]);
	}
	num = 48;
}

void generate_two_whole_table(aes_wb_t aes)
{
	int round = 1;
	// Record the index of the xor table
	int num = 0; 
	// Eight xor table    x2 ^ x3
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, x_inverse_code[2][i], x_inverse_code[3][i], sm4_code[round][i]);
	}
	// Eight xor table   (x2 ^ x3) ^ x4
	num = 8;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][i], sm4_inverse_code[round - 1][72 + i], sm4_code[round][i + 8]);
	}
	num = 16;
	// Four 8-input and 32-output meters
	generate_four_T_table(aes, round, 8, 16);
	// y0 ^ y1
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][16 + i], sm4_inverse_code[round][24 + i], sm4_code[round][48 + i]);
	}
	num = 24;
	// y2 ^ y3
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][32 + i], sm4_inverse_code[round][40 + i], sm4_code[round][56 + i]);
	}
	num = 32;
	// (y0 ^ y1) ^ (y2 ^ y3)
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][48 + i], sm4_inverse_code[round][56 + i], sm4_code[round][64 + i]);
	}
	num = 40;
	// (y0 ^ y1 ^ y2 ^ y3) ^ x0
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][64 + i], x_inverse_code[1][i], sm4_code[round][72 + i]);
	}
	num = 48;
}

void generate_three_whole_table(aes_wb_t aes)
{
	int round = 2;
	int num = 0;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, x_inverse_code[3][i], sm4_inverse_code[round - 2][72 + i], sm4_code[round][i]);
	}
	num = 8;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][i], sm4_inverse_code[round - 1][72 + i], sm4_code[round][i + 8]);
	}
	num = 16;
	generate_four_T_table(aes, round, 8, 16);
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][16 + i], sm4_inverse_code[round][24 + i], sm4_code[round][48 + i]);
	}
	num = 24;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][32 + i], sm4_inverse_code[round][40 + i], sm4_code[round][56 + i]);
	}
	num = 32;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][48 + i], sm4_inverse_code[round][56 + i], sm4_code[round][64 + i]);
	}
	num = 40;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][64 + i], x_inverse_code[2][i], sm4_code[round][72 + i]);
	}
	num = 48;
}
void generate_four_whole_table(aes_wb_t aes)
{
	int round = 3;
	int num = 0;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round - 3][72 + i], sm4_inverse_code[round - 2][72 + i], sm4_code[round][i]);
	}
	num = 8;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][i], sm4_inverse_code[round - 1][72 + i], sm4_code[round][i + 8]);
	}
	num = 16;
	generate_four_T_table(aes, round, 8, 16);
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][16 + i], sm4_inverse_code[round][24 + i], sm4_code[round][48 + i]);
	}
	num = 24;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][32 + i], sm4_inverse_code[round][40 + i], sm4_code[round][56 + i]);
	}
	num = 32;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][48 + i], sm4_inverse_code[round][56 + i], sm4_code[round][64 + i]);
	}
	num = 40;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][64 + i], x_inverse_code[3][i], sm4_code[round][72 + i]);
	}
	num = 48;
}
void generate_five_to_twenty_eight_whole_table(aes_wb_t aes)
{
	for (int round = 4; round < 28; round++)
	{
		int num = 0;
		for (int i = 0; i < 8; i++)
		{
			generator_xor_table(aes, round, i + num, sm4_inverse_code[round - 3][72 + i], sm4_inverse_code[round - 2][72 + i], sm4_code[round][i]);
		}
		num = 8;
		for (int i = 0; i < 8; i++)
		{
			generator_xor_table(aes, round, i + num, sm4_inverse_code[round][i], sm4_inverse_code[round - 1][72 + i], sm4_code[round][i + 8]);
		}
		num = 16;
		generate_four_T_table(aes, round, 8, 16);
		for (int i = 0; i < 8; i++)
		{
			generator_xor_table(aes, round, i + num, sm4_inverse_code[round][16 + i], sm4_inverse_code[round][24 + i], sm4_code[round][48 + i]);
		}
		num = 24;
		for (int i = 0; i < 8; i++)
		{
			generator_xor_table(aes, round, i + num, sm4_inverse_code[round][32 + i], sm4_inverse_code[round][40 + i], sm4_code[round][56 + i]);
		}
		num = 32;
		for (int i = 0; i < 8; i++)
		{
			generator_xor_table(aes, round, i + num, sm4_inverse_code[round][48 + i], sm4_inverse_code[round][56 + i], sm4_code[round][64 + i]);
		}
		num = 40;
		for (int i = 0; i < 8; i++)
		{
			generator_xor_table(aes, round, i + num, sm4_inverse_code[round][64 + i], sm4_inverse_code[round - 4][72 + i], sm4_code[round][72 + i]);
		}
		num = 48;
	}
}
void generate_twenty_nine_whole_table(aes_wb_t aes)
{
	int round = 28;
	int num = 0;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round - 3][72 + i], sm4_inverse_code[round - 2][72 + i], sm4_code[round][i]);
	}
	num = 8;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][i], sm4_inverse_code[round - 1][72 + i], sm4_code[round][i + 8]);
	}
	num = 16;
	generate_four_T_table(aes, round, 8, 16);
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][16 + i], sm4_inverse_code[round][24 + i], sm4_code[round][48 + i]);
	}
	num = 24;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][32 + i], sm4_inverse_code[round][40 + i], sm4_code[round][56 + i]);
	}
	num = 32;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][48 + i], sm4_inverse_code[round][56 + i], sm4_code[round][64 + i]);
	}
	num = 40;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][64 + i], sm4_inverse_code[round - 4][72 + i], x_code[4][i]);
	}
	num = 48;
}
void generate_thirty_whole_table(aes_wb_t aes)
{
	int round = 29;
	int num = 0;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round - 3][72 + i], sm4_inverse_code[round - 2][72 + i], sm4_code[round][i]);
	}
	num = 8;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][i], x_inverse_code[4][i], sm4_code[round][i + 8]);
	}
	num = 16;
	generate_four_T_table(aes, round, 8, 16);
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][16 + i], sm4_inverse_code[round][24 + i], sm4_code[round][48 + i]);
	}
	num = 24;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][32 + i], sm4_inverse_code[round][40 + i], sm4_code[round][56 + i]);
	}
	num = 32;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][48 + i], sm4_inverse_code[round][56 + i], sm4_code[round][64 + i]);
	}
	num = 40;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][64 + i], sm4_inverse_code[round - 4][72 + i], x_code[5][i]);
	}
	num = 48;
}
void generate_thirty_one_whole_table(aes_wb_t aes)
{
	int round = 30;
	int num = 0;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round - 3][72 + i], x_inverse_code[4][i], sm4_code[round][i]);
	}
	num = 8;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][i], x_inverse_code[5][i], sm4_code[round][i + 8]);
	}
	num = 16;
	generate_four_T_table(aes, round, 8, 16);
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][16 + i], sm4_inverse_code[round][24 + i], sm4_code[round][48 + i]);
	}
	num = 24;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][32 + i], sm4_inverse_code[round][40 + i], sm4_code[round][56 + i]);
	}
	num = 32;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][48 + i], sm4_inverse_code[round][56 + i], sm4_code[round][64 + i]);
	}
	num = 40;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][64 + i], sm4_inverse_code[round - 4][72 + i], x_code[6][i]);
	}
	num = 48;
}
void generate_thirty_two_whole_table(aes_wb_t aes)
{
	int round = 31;
	int num = 0;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, x_inverse_code[4][i], x_inverse_code[5][i], sm4_code[round][i]);
	}
	num = 8;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][i], x_inverse_code[6][i], sm4_code[round][i + 8]);
	}
	num = 16;
	generate_four_T_table(aes, round, 8, 16);
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][16 + i], sm4_inverse_code[round][24 + i], sm4_code[round][48 + i]);
	}
	num = 24;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][32 + i], sm4_inverse_code[round][40 + i], sm4_code[round][56 + i]);
	}
	num = 32;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][48 + i], sm4_inverse_code[round][56 + i], sm4_code[round][64 + i]);
	}
	num = 40;
	for (int i = 0; i < 8; i++)
	{
		generator_xor_table(aes, round, i + num, sm4_inverse_code[round][64 + i], sm4_inverse_code[round - 4][72 + i], x_code[7][i]);
	}
	num = 48;
}

// Generate all tables
void generate_table(aes_wb_t aes)
{
	generate_one_whole_table(aes);
	generate_two_whole_table(aes);
	generate_three_whole_table(aes);
	generate_four_whole_table(aes);
	generate_five_to_twenty_eight_whole_table(aes);
	generate_twenty_nine_whole_table(aes);
	generate_thirty_whole_table(aes);
	generate_thirty_one_whole_table(aes);
	generate_thirty_two_whole_table(aes);
}

// SM4 Encryption functions
void sm4_enc(aes_wb_t aes, u32* m, u32* X, u32* c)
{
	for (int i = 0; i < 4; i++)
	{
		X[i] = m[i];
	}
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
			temp_list_u4[i] = aes->xor_table[round][i][Xi1[i]][Xi2[i]];
		}
		for (int i = 0; i < 8; i++)
		{
			temp_list_u4[i] = aes->xor_table[round][i + 8][temp_list_u4[i]][Xi3[i]];
		}
		// Lookup the 8-in 32-out table
		u4_to_u32(temp_list_u4, &temp);
		u8 temp_list_u8[4] = { 0 };
		u32_to_u8(temp, temp_list_u8);

		u32 y0 = aes->T[round][0][temp_list_u8[0]];
		u32 y1 = aes->T[round][1][temp_list_u8[1]];
		u32 y2 = aes->T[round][2][temp_list_u8[2]];
		u32 y3 = aes->T[round][3][temp_list_u8[3]];
		u8 y0_u4[8] = { 0 }; u8 y1_u4[8] = { 0 }; u8 y2_u4[8] = { 0 }; u8 y3_u4[8] = { 0 };
		u32_to_u4(y0, y0_u4); u32_to_u4(y1, y1_u4); u32_to_u4(y2, y2_u4); u32_to_u4(y3, y3_u4);
		u8 temp_round_output1[8] = { 0 };
		u8 temp_round_output2[8] = { 0 };
		for (int i = 0; i < 8; i++)
		{
			temp_round_output1[i] = aes->xor_table[round][16 + i][y0_u4[i]][y1_u4[i]];
		}
		for (int i = 0; i < 8; i++)
		{
			temp_round_output2[i] = aes->xor_table[round][24 + i][y2_u4[i]][y3_u4[i]];
		}
		for (int i = 0; i < 8; i++)
		{
			temp_round_output1[i] = aes->xor_table[round][32 + i][temp_round_output1[i]][temp_round_output2[i]];
		}
		for(int i=0;i<8;i++)
		{
			temp_round_output1[i] = aes->xor_table[round][40 + i][temp_round_output1[i]][Xi0[i]];
		}
		u4_to_u32(temp_round_output1, &X[round + 4]);
	}
	for (int i = 0; i < 4; i++)
	{
		c[i] = X[35 - i];
	}
}

// Writing the T table to a file
static void Print_T(FILE* table)
{
	// Writing the T table to a file
	fprintf(table, "u32 T[32][4][256] = {");
	for (int i = 0; i < 32; i++)
	{
		fprintf(table, "{");
		for (int j = 0; j < 4; j++)
		{
			fprintf(table, "{");
			for (int k = 0; k < 256; k++)
			{
				fprintf(table, "%s%08lX", "0x", aes.T[i][j][k]);
				if (k < 255)
				{
					fprintf(table, ",");
				}
			}
			fprintf(table, "}");
			if (j < 3)
			{
				fprintf(table, ",");
			}
		}
		fprintf(table, "}");
		if (i < 31)
		{
			fprintf(table, ",");
		}
	}
	fprintf(table, "};\n");
}

// Writing xor tables to a file
static void Print_Xor(FILE* table)
{
	fprintf(table, "u8 xor_table[32][48][16][16] = {");
	for (int i = 0; i < 32; i++)
	{
		fprintf(table, "{");
		for (int j = 0; j < 48; j++)
		{
			fprintf(table, "{");
			for (int k = 0; k < 16; k++)
			{
				fprintf(table, "{");
				for (int q = 0; q < 16; q++)
				{
					fprintf(table, "%s%X", "0x", aes.xor_table[i][j][k][q]);
					if (q < 15)
					{
						fprintf(table, ",");
					}
				}
				fprintf(table, "}");
				if (k < 15)
				{
					fprintf(table, ",");
				}
			}
			fprintf(table, "}");
			if (j < 47)
			{
				fprintf(table, ",");
			}
		}
		fprintf(table, "}");
		if (i < 31)
		{
			fprintf(table, ",");
		}
	}
	fprintf(table, "};\n");
}

static void PrintAll(FILE* table)
{
	fprintf(table, "#define u8 unsigned char\n#define u32 unsigned long\n\n\n\n");
	Print_T(table);
	Print_Xor(table);
}
int main()
{
	Key_Schedule(Key_List, MK);
	srand((unsigned)time(NULL));
	generate_inter_code();
	generate_table(&aes);
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
	sm4_enc(&aes, m, X, c);
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
	printf("\n\n");
	FILE* tableFile;
	tableFile = fopen("table.h", "w+");
	if (tableFile != NULL)
	{
		PrintAll(tableFile);
		fclose(tableFile);
	}
}


