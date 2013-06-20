/*
 * This file is part of CertiVox M-Pin Client and Server Libraries. 

The CertiVox M-Pin Client and Server Libraries provides developers with an extensive and efficient set of strong authentication and cryptographic functions. 

For further information about its features and functionalities please refer to http://www.certivox.com 

The CertiVox M-Pin Client and Server Libraries are free software: you can redistribute it and/or modify it under the terms of the BSD 3-Clause License http://opensource.org/licenses/BSD-3-Clause as stated below.

The CertiVox M-Pin Client and Server Libraries are distributed in the hope that they will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 

Note that CertiVox Ltd. issues a patent grant for use of this software under specific terms and conditions, which you can find here: http://certivox.com/about-certivox/patents/ 

Copyright (c) 2013, CertiVox UK Ltd
All rights reserved.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
•  Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
•  Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
•  Neither the name of CertiVox Ltd nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


/*
 *  Common header file
 *  Author: M. Scott 2012
 */

#ifndef CERTIVOX_H
#define CERTIVOX_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "miracl.h"
#include "octet.h"

/* Note that all of this code standardises on 112/128-bit symmetric keys, and 256-bit Hash Functions */

#define TIME_SLOT_MINUTES 1440 /* Time Slot = 1 day */
//#define TIME_SLOT_MINUTES 1  /* Time Slot = 1 minute */

#define HASH_BYTES 32

#if HASH_BYTES==20
	#define HASHFUNC sha
	#define SHS_INIT shs_init
	#define SHS_PROCESS shs_process
	#define SHS_HASH shs_hash
	#define HASH_BLOCK 64
#endif

#if HASH_BYTES==32
	#define HASHFUNC sha256
	#define SHS_INIT shs256_init
	#define SHS_PROCESS shs256_process
	#define SHS_HASH shs256_hash
	#define HASH_BLOCK 64
#endif

#if HASH_BYTES==48
	#define HASHFUNC sha384
	#define SHS_INIT shs384_init
	#define SHS_PROCESS shs384_process
	#define SHS_HASH shs384_hash
	#define HASH_BLOCK 128
#endif

#if HASH_BYTES==64
	#define HASHFUNC sha512
	#define SHS_INIT shs512_init
	#define SHS_PROCESS shs512_process
	#define SHS_HASH shs512_hash
	#define HASH_BLOCK 128
#endif

/* Random Number Functions */

extern void CREATE_CSPRNG(csprng *,octet *);
extern void KILL_CSPRNG(csprng *);

/* Generate  random number generator */
extern csprng generateRNG(char* seedValue);

typedef struct
{
    zzn4 a;
    zzn4 b;
	zzn4 c;
    BOOL unitary;
	BOOL miller;
} zzn12;

extern mr_unsign32 today(void);
/* extern mr_unsign32 getdate(char *); */
extern void thedate(mr_unsign32 ,char *);
extern void int_to_base64(int , char *);
extern int base64_to_int(char *);
extern void hash(octet *,int ,octet *,octet *,octet *);
extern void HashToIntegerRange(_MIPT_ big ,big ,big );

extern void zzn2_alloc(_MIPT_ zzn2 *,char *,int *);
extern void zzn4_alloc(_MIPT_ zzn4 *,char *,int *);
extern void zzn12_alloc(_MIPT_ zzn12 *,char *,int *);
extern void zzn12_powq(_MIPT_ zzn2 *,zzn12 *);
extern BOOL zzn12_iszero(zzn12 *);
extern BOOL zzn12_isunity(_MIPT_ zzn12 *);
extern void zzn12_copy(zzn12 *,zzn12 *);
extern void zzn12_from_int(_MIPT_ int ,zzn12 *);
extern void zzn12_from_zzn4s(zzn4 *,zzn4 *,zzn4 *,zzn12 *);
extern void zzn12_conj(_MIPT_ zzn12 *,zzn12 *);
extern BOOL zzn12_compare(zzn12 *,zzn12 *);
extern void zzn12_sqr(_MIPT_ zzn12 *,zzn12 *);
extern void zzn12_mul(_MIPT_ zzn12 *,zzn12 *,zzn12 *);
extern void zzn12_inv(_MIPT_ zzn12 *);
extern void zzn12_pow(_MIPT_ zzn12 *,big ,zzn12 *);
extern void xtr_A(_MIPT_ zzn4 *,zzn4 *,zzn4 *,zzn4 *,zzn4 *);
extern void xtr_D(_MIPT_ zzn4 *,zzn4 *);
extern void xtr_pow(_MIPT_ zzn4 *,big ,zzn4 *);
extern void xtr_pow2(_MIPT_ zzn4 *,zzn4 *,zzn4 *,zzn4 *,big ,big ,zzn4 *);

extern void endomorph(_MIPT_ big ,epoint *);
extern void q_power_frobenius(_MIPT_ zzn2 *,ecn2 *);
extern void line(_MIPT_ ecn2 *,ecn2 *,ecn2 *,zzn2 *,zzn2 *,BOOL ,big,big,zzn12 *);
extern void g(_MIPT_ ecn2* ,ecn2 *,big ,big ,zzn12 *);
extern BOOL rate_double_miller(_MIPT_ ecn2 *,epoint *,ecn2 *,epoint *,big ,zzn2 *,zzn12 *);
extern BOOL rate_miller(_MIPT_ ecn2 *,epoint *,big ,zzn2 *,zzn12 *);
extern void rate_fexp(_MIPT_ big ,zzn2 *,zzn12 *);
extern void cofactor(_MIPT_ zzn2 *,big ,ecn2 *);
extern BOOL member(_MIPT_ zzn2 *,big ,zzn12 *);
extern void glv(_MIPT_ big ,big ,big W[2],big B[2][2],big u[2]);
extern void galscott(_MIPT_ big ,big ,big W[4],big B[4][4],big u[4]);
extern void getprb(_MIPT_ big ,big ,big ,big);
extern void matrix2(_MIPT_ big ,big W[2],big B[2][2]);
extern void matrix4(_MIPT_ big ,big W[4],big B[4][4]);
extern void G1_mult(_MIPT_ epoint *,big ,big ,big ,big ,epoint *);
extern void G2_mult(_MIPT_ ecn2 *,big ,zzn2 *,big ,big ,ecn2 *);

extern void AES_KEY(csprng *,octet *);
extern void AES_GCM_ENCRYPT(octet *,octet *,octet *,octet *,octet *,octet *);
extern void AES_GCM_DECRYPT(octet *,octet *,octet *,octet *,octet *,octet *);

#endif
