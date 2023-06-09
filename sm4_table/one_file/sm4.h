#ifndef _SM4_H_
#define _SM4_H_
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#define u8 unsigned char
#define u32 unsigned long

/******************************Define the value of the system parameter FK****************************************/
const u32 TBL_SYS_PARAMS_FK[4] = {
	0xa3b1bac6,
	0x56aa3350,
	0x677d9197,
	0xb27022dc
};

/******************************Define the value of the fixed parameter CK****************************************/
const u32 TBL_FIX_PARAMS_CK[32] = {

	0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
	0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
	0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
	0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
	0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
	0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
	0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
	0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

/******************************SBox parameter list****************************************/
const u8 TBL_SBOX[256] = {

	0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
	0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
	0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
	0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
	0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
	0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
	0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
	0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
	0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
	0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
	0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
	0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
	0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
	0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
	0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
	0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

/***********************************The matrix of the linear transformation L*********************************/
const u8 B1[8] = { 0xA0,0x50,0x28,0x14,0x0A,0x05,0x02,0x01 };
const u8 B2[8] = { 0x20,0x10,0x08,0x04,0x02,0x01,0x80,0x40 };
const u8 B3[8] = { 0x80,0x40,0x20,0x10,0x08,0x04,0x82,0x41 };

/******************************Randomly generate SBox parameters in 4bit encoding****************************/
const u8 Coding_SBOX[16] = {
	0x0E,0x04,0x0D,0x01,0x02,0x0F,0x0B, 0x08,
	0x03,0x0A,0x06,0x0C,0x05,0x09,0x00,0x07
};

// Multiplication of GF(2^8)
u8 mod_mul(u8 hex1, u8 hex2)
{
	int a[16], b[16], s[32];
	u8 n = hex2, cnt = 0;
	// Convert to binary
	while (n)  
	{
		s[cnt++] = n % 2;
		n /= 2;
	}
	a[1] = 0x01, b[1] = hex1;
	for (int i = 2; i <= 8; i++)
		// get 0x01 0x02 0x04 0x08 0x10 0x20 0x40 0x80
		a[i] = a[i - 1] << 1;  
	for (int i = 2; i <= 8; i++)
	{
		// If the highest is 1, take the modulus of the integrable polynomial, otherwise shift left directly
		if (b[i - 1] & 0x80) 
			b[i] = ((b[i - 1] << 1) ^ 0x1B);
		else
			b[i] = b[i - 1] << 1;
		// Take the last two digits directly
		b[i] &= 0xFF; 
	}
	u8 hex = 0x00;
	for (int i = 7; i >= 0; i--)
	{
		// Only when this bit of the binary is 1 can it be iso-or
		if (s[i] == 1)
			hex ^= b[i + 1];
	}
	return hex;
}


// Convert to binary arrays
void to_bin(u8 n, u8* a)
{
	int i = 7;
	while (n > 0)
	{
		a[i] = (u8)n % 2;
		i = i - 1;
		n = n / 2;
	}
}

// Cyclic left shift
u32 left_move(u32 data, int bit_length)
{
	u32 result = 0;
	result = (data << bit_length) ^ (data >> (32 - bit_length));
	return result;
}

// Matrix multiplication
u8 matrix_mul(const u8* B, u8 x)
{
	u8 result = 0;
	for (int i = 0; i < 8; i++)
	{
		u8 Bi_List[8] = { 0 }; u8 x_List[8] = { 0 };
		to_bin(B[i], Bi_List); to_bin(x, x_List);
		u8 temp = Bi_List[0] * x_List[0];
		for (int j = 1; j < 8; j++)
		{
			temp ^= Bi_List[j] * x_List[j];
		}
		result += temp << (8 - i - 1);
	}
	return result;
}

// Calculate the first 8-in-32-out
void cal_y0(u8 x, u8* y0)
{
	y0[0] = matrix_mul(B1, x);
	y0[1] = matrix_mul(B3, x);
	y0[2] = matrix_mul(B2, x);
	y0[3] = matrix_mul(B2, x);
}

// Calculate the second 8-in-32-out
void cal_y1(u8 x, u8* y1)
{
	y1[0] = matrix_mul(B2, x);
	y1[1] = matrix_mul(B1, x);
	y1[2] = matrix_mul(B3, x);
	y1[3] = matrix_mul(B2, x);
}
// Calculate the third 8-in-32-out
void cal_y2(u8 x, u8* y2)
{
	y2[0] = matrix_mul(B2, x);
	y2[1] = matrix_mul(B2, x);
	y2[2] = matrix_mul(B1, x);
	y2[3] = matrix_mul(B3, x);
}
// Calculate the fourth 8-in-32-out
void cal_y3(u8 x, u8* y3)
{
	y3[0] = matrix_mul(B3, x);
	y3[1] = matrix_mul(B2, x);
	y3[2] = matrix_mul(B2, x);
	y3[3] = matrix_mul(B1, x);
}

#endif

#pragma once
