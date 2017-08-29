#include "Lyra2RE.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sha3/sph_blake.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "Lyra2.h"

void lyra2re_hash(const char* input, char* output)
{
    sph_blake256_context     ctx_blake;
    sph_groestl256_context   ctx_groestl;
    sph_keccak256_context    ctx_keccak;
    sph_skein256_context     ctx_skein;

    uint32_t hashA[8], hashB[8];

    sph_blake256_init(&ctx_blake);
    sph_blake256 (&ctx_blake, input, 80);
    sph_blake256_close (&ctx_blake, hashA);

    sph_keccak256_init(&ctx_keccak);
    sph_keccak256 (&ctx_keccak,hashA, 32);
    sph_keccak256_close(&ctx_keccak, hashB);

	LYRA2_old(hashA, 32, hashB, 32, hashB, 32, 1, 8, 8);

	sph_skein256_init(&ctx_skein);
    sph_skein256 (&ctx_skein, hashA, 32);
    sph_skein256_close(&ctx_skein, hashB);

    sph_groestl256_init(&ctx_groestl);
    sph_groestl256 (&ctx_groestl, hashB, 32);
    sph_groestl256_close(&ctx_groestl, hashA);

	memcpy(output, hashA, 32);
}

void lyra2re2_hash(const char* input, char* output)
{
	sph_blake256_context ctx_blake;
	sph_cubehash256_context ctx_cubehash;
	sph_keccak256_context ctx_keccak;
	sph_skein256_context ctx_skein;
	sph_bmw256_context ctx_bmw;

	uint32_t hashA[8], hashB[8];

	sph_blake256_init(&ctx_blake);
    sph_blake256(&ctx_blake, input, 80);
    sph_blake256_close (&ctx_blake, hashA);

    sph_keccak256_init(&ctx_keccak);
    sph_keccak256(&ctx_keccak, hashA, 32);
    sph_keccak256_close(&ctx_keccak, hashB);

    sph_cubehash256_init(&ctx_cubehash);
    sph_cubehash256(&ctx_cubehash, hashB, 32);
    sph_cubehash256_close(&ctx_cubehash, hashA);

    LYRA2(hashB, 32, hashA, 32, hashA, 32, 1, 4, 4);

   	sph_skein256_init(&ctx_skein);
    sph_skein256(&ctx_skein, hashB, 32);
    sph_skein256_close(&ctx_skein, hashA);

    sph_cubehash256_init(&ctx_cubehash);
    sph_cubehash256(&ctx_cubehash, hashA, 32);
    sph_cubehash256_close(&ctx_cubehash, hashB);

    sph_bmw256_init(&ctx_bmw);
    sph_bmw256(&ctx_bmw, hashB, 32);
    sph_bmw256_close(&ctx_bmw, hashA);

   	memcpy(output, hashA, 32);
}