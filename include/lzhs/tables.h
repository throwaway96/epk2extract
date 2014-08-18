#ifndef _LZHS_TAB_H
#define _LZHS_TAB_H
#include <lzhs/lzhs.h>
uint8_t char_len_table[2304] = { //(2304 / 8) => 288 records
	0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 
	0x0A, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 
	0x29, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 
	0x2B, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 
	0x2D, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x2E, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 
	0x2F, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x8A, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0x8B, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x8C, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0x8D, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x8E, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0x30, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x8F, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0x90, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x91, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x81, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x82, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x83, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x31, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x92, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0x93, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0x0B, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x84, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x85, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x86, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x0C, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 
	0x33, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x95, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0x96, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x97, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0x87, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x88, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x34, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0x99, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x89, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x9A, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x9B, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0x8A, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x8B, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x35, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x9C, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0x9D, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x8C, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x8D, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x8E, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x8F, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x9E, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x91, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x92, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x93, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x94, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x95, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x96, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x97, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x36, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x9F, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0x37, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 
	0x98, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x99, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xA0, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x9A, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x39, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x3A, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 
	0x3B, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0xA1, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0xA2, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xA3, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0x9B, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x9C, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x9D, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x9E, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x9F, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xA0, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xA1, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xB0, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xB1, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xB2, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xA2, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xA3, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xA4, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xB3, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xA5, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xB4, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xB5, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xB6, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0x3C, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0xA5, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xA6, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0xA7, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xA8, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0xA6, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xB7, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0x0D, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0xA9, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0xA7, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xA8, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xA9, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xAA, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xAB, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xAC, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0x3D, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0xAD, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xAA, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xAE, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xAF, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xB0, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xB8, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xB9, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0x3E, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0xB1, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xB2, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xB3, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xBA, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xBB, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xBC, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xBD, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0x3F, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0xAB, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0xB4, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xB5, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xB6, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xBE, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xBF, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xC0, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xAC, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xAD, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0xB7, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xB8, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xB9, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xC1, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xC2, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xC3, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xAE, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xAF, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0xB0, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xC4, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xC5, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xC6, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xC7, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xC8, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0x40, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0xB1, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0xBA, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xBB, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xC9, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xCA, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xCB, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xCC, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xB2, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xB3, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0xCD, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xCE, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xCF, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xD0, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xD1, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xDE, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0xB4, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xBC, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xBD, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xBE, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xD2, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xD3, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xDF, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0xE0, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0xB5, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xD4, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xD5, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xE1, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0xD6, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xB6, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0xD7, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xE2, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0xD8, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xE3, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0xE4, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0xE5, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0xD9, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xB7, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0xE6, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0xE7, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0xB8, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xBF, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xDA, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xDB, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xDC, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xE8, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0xE9, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0xEA, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0xC0, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xC1, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xDD, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xEB, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0xDE, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xEC, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0xED, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0xEE, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0x0E, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
	0xC2, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xC3, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xDF, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xC4, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xEF, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0xF0, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0xC5, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xC6, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xE0, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xE1, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xC7, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xE2, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xF1, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0xF2, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0x10, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0xC8, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xC9, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xE3, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xE4, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xCA, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xCB, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 
	0xCC, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xCD, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xCE, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xE5, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xE6, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xE7, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xE8, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xE9, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0x42, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0xF3, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0xF4, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0xEA, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xF5, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0xCF, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xD0, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xBA, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xD1, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xD2, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xD3, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xD4, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xD5, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xBB, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x43, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 
	0x11, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
	0x13, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 
	0xBC, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xBD, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 
	0xBE, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xD6, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 
	0xD7, 0x01, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0xEB, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xEC, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xED, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 
	0xEE, 0x03, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0xF6, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0xF7, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0xF8, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0xF9, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0xFA, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 
	0xFB, 0x07, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0xF8, 0x0F, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 
	0xF9, 0x0F, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0xFA, 0x0F, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 
	0xFB, 0x0F, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0xFC, 0x1F, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 
	0xFC, 0x0F, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0xFD, 0x1F, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 
	0xFD, 0x0F, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0xFE, 0x1F, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 
	0xFF, 0x1F, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 0xBF, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00
};

uint8_t pos_table[256] = { //(256 / 8) => 32 records
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 
	0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 
	0x0F, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 
	0x11, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 
	0x13, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 
	0x2A, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x2B, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
	0x2C, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x2D, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
	0x2E, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x2F, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
	0x30, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
	0x32, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x33, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
	0x34, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
	0x36, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
	0x38, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
	0x3A, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x3B, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
	0x3C, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x3D, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 
	0x3E, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00
};
#endif
