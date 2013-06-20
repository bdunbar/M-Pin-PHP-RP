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

/* test driver and function exerciser for ECCSI Functions */

/* define this next to use Windows DLL */
/* #define ECCSI_DLL  */

/* Use this mirdef.h for 32-bit processor 

#define MR_LITTLE_ENDIAN
#define MIRACL 32
#define mr_utype int
#define mr_dltype long long  
#define mr_unsign64 unsigned long long
#define MR_IBITS 32
#define MR_LBITS 32
#define mr_unsign32 unsigned int
#define MR_ALWAYS_BINARY
#define MR_STATIC 8
#define MR_GENERIC_MT
#define MR_STRIPPED_DOWN
#define MR_NOSUPPORT_COMPRESSION
#define MR_SIMPLE_BASE
#define MR_SIMPLE_IO
#define MR_NOASM
#define MAXBASE ((mr_small)1<<(MIRACL-1))
#define MR_BITSINCHAR 8
*/

/* Use this mirdef.h for 64-bit processor 

#define MR_LITTLE_ENDIAN
#define MIRACL 64
#define mr_utype long long
#define mr_unsign64 unsigned long long
#define MR_IBITS 32
#define MR_LBITS 32
#define mr_unsign32 unsigned int
#define MR_ALWAYS_BINARY
#define MR_STATIC 4
#define MR_GENERIC_MT
#define MR_STRIPPED_DOWN
#define MR_NOSUPPORT_COMPRESSION
#define MR_SIMPLE_BASE
#define MR_SIMPLE_IO
#define MAXBASE ((mr_small)1<<(MIRACL-1))
#define MR_BITSINCHAR 8

*/

/* Link to these files 

mrcore.c
mrarth0.c
mrarth1.c
mrarth2.c
mrio1.c
mrgcd.c
mrxgcd.c
mrarth3.c
mrbits.c
mrmonty.c
mrcurve.c
mrshs256.c
mrstrong.c

For 64-bit build using Microsoft compiler mrmuldv.w64 must be included as well
For 64-bit build using Linux and Intel chips, mrmuldv.g64 must be included as well

However note that this code will also work with a standard MIRACL header

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "eccsi_c.h"

/* Elliptic Curve parameters */

#if MIRACL==64

const mr_small esrom[]={
0xffffffffffffffff,0xffffffff,0x0,0xffffffff00000001,
0x3bce3c3e27d2604b,0x651d06b0cc53b0f6,0xb3ebbd55769886bc,0x5ac635d8aa3a93e7,
0xf3b9cac2fc632551,0xbce6faada7179e84,0xffffffffffffffff,0xffffffff00000000,
0xf4a13945d898c296,0x77037d812deb33a0,0xf8bce6e563a440f2,0x6b17d1f2e12c4247,
0xcbb6406837bf51f5,0x2bce33576b315ece,0x8ee7eb4a7c0f9e16,0x4fe342e2fe1a7f9b};

#endif

#if MIRACL==32

const mr_small esrom[]={
0xffffffff,0xffffffff,0xffffffff,0x0,0x0,0x0,0x1,0xffffffff,
0x27d2604b,0x3bce3c3e,0xcc53b0f6,0x651d06b0,0x769886bc,0xb3ebbd55,0xaa3a93e7,0x5ac635d8,
0xfc632551,0xf3b9cac2,0xa7179e84,0xbce6faad,0xffffffff,0xffffffff,0x0,0xffffffff,
0xd898c296,0xf4a13945,0x2deb33a0,0x77037d81,0x63a440f2,0xf8bce6e5,0xe12c4247,0x6b17d1f2,
0x37bf51f5,0xcbb64068,0x6b315ece,0x2bce3357,0x7c0f9e16,0x8ee7eb4a,0xfe1a7f9b,0x4fe342e2};

#endif


/*** EC GF(p) primitives - support functions ***/
/* destroy the EC GF(p) domain structure */

void ECS_DOMAIN_KILL(ecs_domain *DOM)
{
	int i;
	for (i=0;i<EFS;i++)
	{
		DOM->Q[i]=0;
		DOM->A[i]=0;
		DOM->B[i]=0;
		DOM->R[i]=0;
		DOM->Gx[i]=0;
		DOM->Gy[i]=0;
	}
	for (i=0;i<EGS;i++)
		DOM->R[i]=0;
}

/* Initialise the EC GF(p) domain structure
 * It is assumed that the EC domain details are obtained from ROM
 */

int ECS_DOMAIN_INIT(ecs_domain *DOM,const void *rom)
{ /* get domain details from ROM     */
 
#ifdef MR_GENERIC_AND_STATIC
	miracl instance;
	miracl *mr_mip=mirsys(&instance,2*EFS,16);
#else
    miracl *mr_mip=mirsys(2*EFS,16);
#endif
    big q,r,gx,gy,a,b;
    int words,promptr,err,res=0;
#ifndef MR_STATIC
    char *mem=(char *)memalloc(_MIPP_ 6);;
#else
    char mem[MR_BIG_RESERVE(6)];
    memset(mem,0,MR_BIG_RESERVE(6));
#endif
	DOM->nibbles=2*EFS;
	words=MR_ROUNDUP(EFS*8,MIRACL);

	if (mr_mip==NULL || mem==NULL) res= ECCSI_OUT_OF_MEMORY;

    mr_mip->ERCON=TRUE;

    if (res==0)
    {
        q=mirvar_mem(_MIPP_ mem, 0);
        a=mirvar_mem(_MIPP_ mem, 1);
        b=mirvar_mem(_MIPP_ mem, 2);
        r=mirvar_mem(_MIPP_ mem, 3);
        gx=mirvar_mem(_MIPP_ mem, 4);
        gy=mirvar_mem(_MIPP_ mem, 5);

		promptr=0;
		init_big_from_rom(q,words,(const mr_small *)rom,words*5,&promptr);  /* Read in prime modulus q from ROM   */
		init_big_from_rom(b,words,(const mr_small *)rom,words*5,&promptr);  /* Read in curve parameter b from ROM */
 		init_big_from_rom(r,words,(const mr_small *)rom,words*5,&promptr);  /* Read in curve parameter r from ROM */
 		init_big_from_rom(gx,words,(const mr_small *)rom,words*5,&promptr);  /* Read in curve parameter gx from ROM */
		init_big_from_rom(gy,words,(const mr_small *)rom,words*5,&promptr);  /* Read in curve parameter gy from ROM */
		convert(_MIPP_ -3,a);
		add(_MIPP_ q,a,a);

		big_to_bytes(_MIPP_ EFS,q,DOM->Q,TRUE);
		big_to_bytes(_MIPP_ EFS,a,DOM->A,TRUE);
		big_to_bytes(_MIPP_ EFS,b,DOM->B,TRUE);
		big_to_bytes(_MIPP_ EGS,r,DOM->R,TRUE);
		big_to_bytes(_MIPP_ EFS,gx,DOM->Gx,TRUE);
		big_to_bytes(_MIPP_ EFS,gy,DOM->Gy,TRUE);
	}
#ifndef MR_STATIC
    memkill(_MIPP_ mem,6);
#else
    memset(mem,0,MR_BIG_RESERVE(6));
#endif
    err=mr_mip->ERNUM;
    mirexit(_MIPPO_ );
    if (err==MR_ERR_OUT_OF_MEMORY) return ECCSI_OUT_OF_MEMORY;
    if (err==MR_ERR_DIV_BY_ZERO) return ECCSI_DIV_BY_ZERO;
    if (err!=0) return -(1000+err);
    return res;
}


/* Parameters
DOM - ECC Domain
date - 0 to validate a secret key or a date to validate a time permit
ID - Identity
KPAK - Key Distribution Centre Public Key 
PVT - Private Signing Key, or Time Permit
*/

int ECCSI_USER_KEY_VALIDATE(ecs_domain *DOM,int date,octet *ID,octet *KPAK,octet *PVT)
{
#ifdef MR_GENERIC_AND_STATIC
	miracl instance;
	miracl *mr_mip=mirsys(&instance,DOM->nibbles,16);
#else
	miracl *mr_mip=mirsys(DOM->nibbles,16);
#endif
	int i,n;
    char hh[HASH_BYTES];
	HASHFUNC SHA;
    big q,a,b,r,gx,gy,wx,wy,hs;
    epoint *G,*WP;
    int err,res=0;
#ifndef MR_STATIC
    char *mem=(char *)memalloc(_MIPP_ 9);
    char *mem1=(char *)ecp_memalloc(_MIPP_ 2);
#else
    char mem[MR_BIG_RESERVE(9)];
    char mem1[MR_ECP_RESERVE(2)];
    memset(mem,0,MR_BIG_RESERVE(9));
    memset(mem1,0,MR_ECP_RESERVE(2));
#endif
 
    if (mr_mip==NULL || mem==NULL || mem1==NULL) res= ECCSI_OUT_OF_MEMORY;
    mr_mip->ERCON=TRUE;

    if (res==0)
    {
        q=mirvar_mem(_MIPP_ mem, 0);
        a=mirvar_mem(_MIPP_ mem, 1);
        b=mirvar_mem(_MIPP_ mem, 2);
        r=mirvar_mem(_MIPP_ mem, 3);
        gx=mirvar_mem(_MIPP_ mem, 4);
        gy=mirvar_mem(_MIPP_ mem, 5);
        wx=mirvar_mem(_MIPP_ mem, 6);
        wy=mirvar_mem(_MIPP_ mem, 7);
		hs=mirvar_mem(_MIPP_ mem, 8);

        bytes_to_big(_MIPP_ EFS,DOM->Q,q);
        bytes_to_big(_MIPP_ EFS,DOM->A,a);
        bytes_to_big(_MIPP_ EFS,DOM->B,b);
        bytes_to_big(_MIPP_ EGS,DOM->R,r);
        bytes_to_big(_MIPP_ EFS,DOM->Gx,gx);
        bytes_to_big(_MIPP_ EFS,DOM->Gy,gy);

        ecurve_init(_MIPP_ a,b,q,MR_PROJECTIVE);
        G=epoint_init_mem(_MIPP_ mem1,0);
		WP=epoint_init_mem(_MIPP_ mem1,1);
		if (!epoint_set(_MIPP_ gx,gy,0,G)) res=MR_ERR_BAD_PARAMETERS;
	}
	if (res==0)
	{
		bytes_to_big(_MIPP_ EFS,&(PVT->val[1]),wx);
		bytes_to_big(_MIPP_ EFS,&(PVT->val[EFS+1]),wy);

		if (!epoint_set(_MIPP_ wx,wy,0,WP)) res=ECCSI_INVALID_POINT;
	}
	if (res==0)
	{
		SHS_INIT(&SHA);
		if (date!=0)
		{
			n=date;
			SHS_PROCESS(&SHA,(n>>24)&0xff);
			SHS_PROCESS(&SHA,(n>>16)&0xff);
			SHS_PROCESS(&SHA,(n>>8)&0xff);
			SHS_PROCESS(&SHA,n&0xff);
		}
/* first hash G */
		SHS_PROCESS(&SHA,0x04); 
		for (i=0;i<EFS;i++) {SHS_PROCESS(&SHA,DOM->Gx[i]); }
		for (i=0;i<EFS;i++) {SHS_PROCESS(&SHA,DOM->Gy[i]); }
/* then KPAK, ID and PVT */
		for (i=0;i<KPAK->len;i++) {SHS_PROCESS(&SHA,KPAK->val[i]); }
		for (i=0;i<ID->len;i++) {SHS_PROCESS(&SHA,ID->val[i]);  }
		for (i=0;i<2*EFS+1;i++) {SHS_PROCESS(&SHA,PVT->val[i]);   }
		
		SHS_HASH(&SHA,hh);

		bytes_to_big(_MIPP_ HASH_BYTES,hh,hs);
		divide(_MIPP_ hs,r,r);
		bytes_to_big(_MIPP_ EGS,&(PVT->val[2*EFS+1]),wx); /* SSK as was */
		ecurve_mult(_MIPP_ wx,G,G);
		ecurve_mult(_MIPP_ hs,WP,WP);
		ecurve_sub(_MIPP_ WP,G);
		bytes_to_big(_MIPP_ EFS,&(KPAK->val[1]),wx);
		bytes_to_big(_MIPP_ EFS,&(KPAK->val[EFS+1]),wy);

		if (!epoint_set(_MIPP_ wx,wy,0,WP)) res=ECCSI_INVALID_POINT;
	}
	if (res==0)
	{
		if (!epoint_comp(_MIPP_ G,WP)) res=ECCSI_BAD_KEY;
	}

#ifndef MR_STATIC
    memkill(_MIPP_ mem,9);
    ecp_memkill(_MIPP_ mem1,2);
#else
    memset(mem,0,MR_BIG_RESERVE(9));
    memset(mem1,0,MR_ECP_RESERVE(2));
#endif
    err=mr_mip->ERNUM;
    mirexit(_MIPPO_ );
    if (err==MR_ERR_OUT_OF_MEMORY) return ECCSI_OUT_OF_MEMORY;
    if (err==MR_ERR_DIV_BY_ZERO) return ECCSI_DIV_BY_ZERO;
    if (err!=0) return -(1000+err);
    return res;
}

/* Parameter
DOM - ECC Domain
RNG - Random Number generator, or NULL
J - Random number, or NULL (one of RNG and J must not be NULL)
M - Message to be signed
ID - Identity of Signer
KPAK - Key Distribution Centre Public Key 
PVT - Signing Key
TPM - Time Permit (can be NULL)
SIG - Signature

ALWAYS sign with today's date

(Note that this doesn't stop a determined individual from signing with an earlier date if he has an old time permit)

*/

int ECCSI_SIGN(ecs_domain *DOM,csprng *RNG,octet* J,octet *M,octet *ID,octet *KPAK,octet *PVT,octet *TPM,octet *SIG)
{
#ifdef MR_GENERIC_AND_STATIC
	miracl instance;
	miracl *mr_mip=mirsys(&instance,DOM->nibbles,16);
#else
	miracl *mr_mip=mirsys(DOM->nibbles,16);
#endif
	int i,m,n;
    char hh[HASH_BYTES],ww[HASH_BYTES];
	char IOBUFF[EGS];
	HASHFUNC SHA;
    big q,a,b,r,gx,gy,wx,wy,he,j;
    epoint *G,*WP;
    int err,res=0;
#ifndef MR_STATIC
    char *mem=(char *)memalloc(_MIPP_ 10);
    char *mem1=(char *)ecp_memalloc(_MIPP_ 2);
#else
    char mem[MR_BIG_RESERVE(10)];
    char mem1[MR_ECP_RESERVE(2)];
    memset(mem,0,MR_BIG_RESERVE(10));
    memset(mem1,0,MR_ECP_RESERVE(2));
#endif
 
    if (mr_mip==NULL || mem==NULL || mem1==NULL) res= ECCSI_OUT_OF_MEMORY;
    mr_mip->ERCON=TRUE;

    if (res==0)
    {

        q=mirvar_mem(_MIPP_ mem, 0);
        a=mirvar_mem(_MIPP_ mem, 1);
        b=mirvar_mem(_MIPP_ mem, 2);
        r=mirvar_mem(_MIPP_ mem, 3);
        gx=mirvar_mem(_MIPP_ mem, 4);
        gy=mirvar_mem(_MIPP_ mem, 5);
		j=mirvar_mem(_MIPP_ mem, 6);
        wx=mirvar_mem(_MIPP_ mem, 7);
        wy=mirvar_mem(_MIPP_ mem, 8);
		he=mirvar_mem(_MIPP_ mem, 9);

        bytes_to_big(_MIPP_ EFS,DOM->Q,q);
        bytes_to_big(_MIPP_ EFS,DOM->A,a);
        bytes_to_big(_MIPP_ EFS,DOM->B,b);
        bytes_to_big(_MIPP_ EGS,DOM->R,r);
        bytes_to_big(_MIPP_ EFS,DOM->Gx,gx);
        bytes_to_big(_MIPP_ EFS,DOM->Gy,gy);

        ecurve_init(_MIPP_ a,b,q,MR_PROJECTIVE);
        G=epoint_init_mem(_MIPP_ mem1,0);
		WP=epoint_init_mem(_MIPP_ mem1,1);
		if (!epoint_set(_MIPP_ gx,gy,0,G))  res=MR_ERR_BAD_PARAMETERS;
	}
	if (res==0)
	{

        if (RNG!=NULL)
            strong_bigrand(_MIPP_ RNG,r,j);
        else
        {
            bytes_to_big(_MIPP_ J->len,J->val,j);
            divide(_MIPP_ j,r,r);
        }
		if (RNG!=NULL && J!=NULL)  J->len=big_to_bytes(_MIPP_ 0,j,J->val,FALSE); 

		ecurve_mult(_MIPP_ j,G,WP);        
		epoint_get(_MIPP_ WP,wx,wy);
		divide(_MIPP_ wx,r,r);

		bytes_to_big(_MIPP_ EGS,&(PVT->val[2*EFS+1]),wy);
		if (TPM!=NULL)
		{
			bytes_to_big(_MIPP_ EGS,&(TPM->val[2*EFS+1]),a);
			add(_MIPP_ wy,a,wy);
		}

		big_to_bytes(_MIPP_ EGS,wx,IOBUFF,TRUE); /* r */

		SHS_INIT(&SHA);
/* first hash G */
		SHS_PROCESS(&SHA,0x04);
		for (i=0;i<EFS;i++) SHS_PROCESS(&SHA,DOM->Gx[i]);
		for (i=0;i<EFS;i++) SHS_PROCESS(&SHA,DOM->Gy[i]);
/* then KPAK, ID and PVT */
		for (i=0;i<KPAK->len;i++) SHS_PROCESS(&SHA,KPAK->val[i]);
		for (i=0;i<ID->len;i++) SHS_PROCESS(&SHA,ID->val[i]);
		for (i=0;i<2*EFS+1;i++) SHS_PROCESS(&SHA,PVT->val[i]);
		
		SHS_HASH(&SHA,hh);

		if (TPM!=NULL)
		{
			SHS_INIT(&SHA);
			n=today();
			SHS_PROCESS(&SHA,(n>>24)&0xff);
			SHS_PROCESS(&SHA,(n>>16)&0xff);
			SHS_PROCESS(&SHA,(n>>8)&0xff);
			SHS_PROCESS(&SHA,n&0xff);
/* first hash G */
			SHS_PROCESS(&SHA,0x04);
			for (i=0;i<EFS;i++) SHS_PROCESS(&SHA,DOM->Gx[i]);
			for (i=0;i<EFS;i++) SHS_PROCESS(&SHA,DOM->Gy[i]);
/* then KPAK, ID and PVT */
			for (i=0;i<KPAK->len;i++) SHS_PROCESS(&SHA,KPAK->val[i]);
			for (i=0;i<ID->len;i++) SHS_PROCESS(&SHA,ID->val[i]);
			for (i=0;i<2*EFS+1;i++) SHS_PROCESS(&SHA,TPM->val[i]);
		
			SHS_HASH(&SHA,ww);
		}

		SHS_INIT(&SHA);
/* first hash HS */
		for (i=0;i<HASH_BYTES;i++) SHS_PROCESS(&SHA,hh[i]);
		if (TPM!=NULL) for (i=0;i<HASH_BYTES;i++) SHS_PROCESS(&SHA,ww[i]);
		
/* then r */
		for (i=0;i<EGS;i++) SHS_PROCESS(&SHA,IOBUFF[i]);
/* finally M.. */
		for (i=0;i<M->len;i++) SHS_PROCESS(&SHA,M->val[i]);
		
		SHS_HASH(&SHA,hh);
		bytes_to_big(_MIPP_ HASH_BYTES,hh,he);

		mad(_MIPP_ wx,wy,he,r,r,wy); /* rk + e  */
		invmodp(_MIPP_ wy,r,wy);
		mad(_MIPP_ wy,j,j,r,r,wy);    /* s' */
		if (logb2(_MIPP_ wx)>EGS*8) subtract(_MIPP_ r,wy,wy); /* s */

		SIG->len=2*EGS+2*EFS+1;
		if (TPM!=NULL) SIG->len=2*EGS+4*EFS+6;
/* SIG = r || s || PVT */	
		for (i=m=0;i<EGS;i++) SIG->val[m++]=IOBUFF[i];
		big_to_bytes(_MIPP_ EGS,wy,IOBUFF,TRUE);
		for (i=0;i<EGS;i++) SIG->val[m++]=IOBUFF[i];
		for (i=0;i<2*EFS+1;i++) SIG->val[m++]=PVT->val[i];

		if (TPM!=NULL)
		{ /* SIG = SIG || TPM || date */ 
			for (i=0;i<2*EFS+1;i++) SIG->val[m++]=TPM->val[i];
			SIG->val[m++]=(n>>24)&0xff;
			SIG->val[m++]=(n>>16)&0xff;
			SIG->val[m++]=(n>>8)&0xff;
			SIG->val[m++]=n&0xff;
		}
	}

#ifndef MR_STATIC
    memkill(_MIPP_ mem,10);
    ecp_memkill(_MIPP_ mem1,2);
#else
    memset(mem,0,MR_BIG_RESERVE(10));
    memset(mem1,0,MR_ECP_RESERVE(2));
#endif
    err=mr_mip->ERNUM;
    mirexit(_MIPPO_ );
    if (err==MR_ERR_OUT_OF_MEMORY) return ECCSI_OUT_OF_MEMORY;
    if (err==MR_ERR_DIV_BY_ZERO) return ECCSI_DIV_BY_ZERO;
    if (err!=0) return -(1000+err);
    return res;
}

/* Parameters
DOM - ECC Domain
type - PERMITS_ON or PERMITS_OFF 
M - Message to be signed
ID - Identity of Signer
KPAK - Key Distrubution Centre Public Key
SIG - Signature

*/

int ECCSI_VERIFY(ecs_domain *DOM,int type,octet *M,octet *ID,octet *KPAK,octet *SIG)
{
#ifdef MR_GENERIC_AND_STATIC
	miracl instance;
	miracl *mr_mip=mirsys(&instance,DOM->nibbles,16);
#else
	miracl *mr_mip=mirsys(DOM->nibbles,16);
#endif
	int i;
    char hh[HASH_BYTES],ww[HASH_BYTES];
	HASHFUNC SHA;
    big q,a,b,r,gx,gy,wx,wy,he,hs;
    epoint *G,*WP;
    int err,res=0;
#ifndef MR_STATIC
    char *mem=(char *)memalloc(_MIPP_ 10);
    char *mem1=(char *)ecp_memalloc(_MIPP_ 2);
#else
    char mem[MR_BIG_RESERVE(10)];
    char mem1[MR_ECP_RESERVE(2)];
    memset(mem,0,MR_BIG_RESERVE(10));
    memset(mem1,0,MR_ECP_RESERVE(2));
#endif
 
    if (mr_mip==NULL || mem==NULL || mem1==NULL) res= ECCSI_OUT_OF_MEMORY;
    mr_mip->ERCON=TRUE;

    if (res==0)
    {
        q=mirvar_mem(_MIPP_ mem, 0);
        a=mirvar_mem(_MIPP_ mem, 1);
        b=mirvar_mem(_MIPP_ mem, 2);
        r=mirvar_mem(_MIPP_ mem, 3);
        gx=mirvar_mem(_MIPP_ mem, 4);
        gy=mirvar_mem(_MIPP_ mem, 5);
		hs=mirvar_mem(_MIPP_ mem, 6);
        wx=mirvar_mem(_MIPP_ mem, 7);
        wy=mirvar_mem(_MIPP_ mem, 8);
		he=mirvar_mem(_MIPP_ mem, 9);

        bytes_to_big(_MIPP_ EFS,DOM->Q,q);
        bytes_to_big(_MIPP_ EFS,DOM->A,a);
        bytes_to_big(_MIPP_ EFS,DOM->B,b);
        bytes_to_big(_MIPP_ EGS,DOM->R,r);

        ecurve_init(_MIPP_ a,b,q,MR_PROJECTIVE);
        G=epoint_init_mem(_MIPP_ mem1,0);
		WP=epoint_init_mem(_MIPP_ mem1,1);

		SHS_INIT(&SHA);
/* first hash G */
		SHS_PROCESS(&SHA,0x04);
		for (i=0;i<EFS;i++) SHS_PROCESS(&SHA,DOM->Gx[i]);
		for (i=0;i<EFS;i++) SHS_PROCESS(&SHA,DOM->Gy[i]);
/* then KPAK, ID and PVT */
		for (i=0;i<KPAK->len;i++) SHS_PROCESS(&SHA,KPAK->val[i]);
		for (i=0;i<ID->len;i++) SHS_PROCESS(&SHA,ID->val[i]);
		for (i=0;i<2*EFS+1;i++) SHS_PROCESS(&SHA,SIG->val[2*EGS+i]);
		
		SHS_HASH(&SHA,hh);

		bytes_to_big(_MIPP_ HASH_BYTES,hh,hs);

		if (type==PERMITS_ON)
		{
			SHS_INIT(&SHA);
			SHS_PROCESS(&SHA,SIG->val[4*EFS+2*EGS+2]); /* process date on signature */
			SHS_PROCESS(&SHA,SIG->val[4*EFS+2*EGS+3]);
			SHS_PROCESS(&SHA,SIG->val[4*EFS+2*EGS+4]);
			SHS_PROCESS(&SHA,SIG->val[4*EFS+2*EGS+5]);
/* first hash G */
			SHS_PROCESS(&SHA,0x04);
			for (i=0;i<EFS;i++) SHS_PROCESS(&SHA,DOM->Gx[i]);
			for (i=0;i<EFS;i++) SHS_PROCESS(&SHA,DOM->Gy[i]);
/* then KPAK, ID and PVT */
			for (i=0;i<KPAK->len;i++) SHS_PROCESS(&SHA,KPAK->val[i]);
			for (i=0;i<ID->len;i++) SHS_PROCESS(&SHA,ID->val[i]);
			for (i=0;i<2*EFS+1;i++) SHS_PROCESS(&SHA,SIG->val[2*EGS+2*EFS+1+i]);
		
			SHS_HASH(&SHA,ww);

			bytes_to_big(_MIPP_ HASH_BYTES,ww,a);
		}

/* extract signature */

		bytes_to_big(_MIPP_ EGS,&SIG->val[0],wx);  /* get r */
		bytes_to_big(_MIPP_ EGS,&SIG->val[EGS],wy); /* get s */

		SHS_INIT(&SHA);
/* first hash HS */
		for (i=0;i<HASH_BYTES;i++) SHS_PROCESS(&SHA,hh[i]);
		if (type==PERMITS_ON) for (i=0;i<HASH_BYTES;i++) SHS_PROCESS(&SHA,ww[i]);
/* then r */
		for (i=0;i<EGS;i++) SHS_PROCESS(&SHA,SIG->val[i]);
/* finally M.. */
		for (i=0;i<M->len;i++) SHS_PROCESS(&SHA,M->val[i]);

		SHS_HASH(&SHA,hh);
		bytes_to_big(_MIPP_ HASH_BYTES,hh,he);

/* Get Public Key P */
		bytes_to_big(_MIPP_ EFS,&(KPAK->val[1]),gx);
		bytes_to_big(_MIPP_ EFS,&(KPAK->val[EFS+1]),gy);
		if (!epoint_set(_MIPP_ gx,gy,0,G)) res=ECCSI_BAD_KEY;
	}
	if (res==0)
	{
/* extract PVT from signature */

		bytes_to_big(_MIPP_ EFS,&(SIG->val[2*EGS+1]),gx);
		bytes_to_big(_MIPP_ EFS,&(SIG->val[2*EGS+EFS+1]),gy);

		if (!epoint_set(_MIPP_ gx,gy,0,WP)) res=ECCSI_INVALID_POINT;
	}
	if (res==0)
	{
		ecurve_mult(_MIPP_ hs,WP,WP);
		ecurve_add(_MIPP_ G,WP);     /* hV+P */
		if (type==PERMITS_ON)
		{
			ecurve_add(_MIPP_ G,WP);
			bytes_to_big(_MIPP_ EFS,&(SIG->val[2*EGS+2*EFS+2]),gx);
			bytes_to_big(_MIPP_ EFS,&(SIG->val[2*EGS+3*EFS+2]),gy);
			if (!epoint_set(_MIPP_ gx,gy,0,G)) res=ECCSI_INVALID_POINT;
			ecurve_mult(_MIPP_ a,G,G);
			ecurve_add(_MIPP_ G,WP);
		}
	}
	if (res==0)
	{

        bytes_to_big(_MIPP_ EFS,DOM->Gx,gx);
        bytes_to_big(_MIPP_ EFS,DOM->Gy,gy);

		if (!epoint_set(_MIPP_ gx,gy,0,G))  res=MR_ERR_BAD_PARAMETERS;
	}
	if (res==0)
	{
		mad(_MIPP_ wx,wy,wx,r,r,hs);
		mad(_MIPP_ wy,he,wy,r,r,wy);
		ecurve_mult2(_MIPP_ hs,WP,wy,G,G);

		epoint_get(_MIPP_ G,gx,gy);

		if (mr_compare(gx,wx)!=0) res=ECCSI_BAD_SIG;
	}

#ifndef MR_STATIC
    memkill(_MIPP_ mem,10);
    ecp_memkill(_MIPP_ mem1,2);
#else
    memset(mem,0,MR_BIG_RESERVE(10));
    memset(mem1,0,MR_ECP_RESERVE(2));
#endif
    err=mr_mip->ERNUM;
    mirexit(_MIPPO_ );
    if (err==MR_ERR_OUT_OF_MEMORY) return ECCSI_OUT_OF_MEMORY;
    if (err==MR_ERR_DIV_BY_ZERO) return ECCSI_DIV_BY_ZERO;
    if (err!=0) return -(1000+err);
    return res;
} 
