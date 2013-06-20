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


/* MPIN Functions */

/* Version 2.0 - supports Time Permits */

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
mraes.c
mrzzn2.c
mrzzn4.c
mrecn2.c
mrsroot.c
mrjack.c
mrlucas.c
mrzzn2b.c

For 64-bit build using Microsoft compiler mrmuldv.w64 must be included as well
For 64-bit build using Linux and Intel chips, mrmuldv.g64 must be included as well

However note that this code will also work with a standard MIRACL header

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "mpin_c.h"

#define ROM_SIZE 8

/*
#if MIRACL==64

const mr_small mprom[]={
0x4080000000000001,0x0,0x0,0x8000000000000000, // x 
0x2,0x0,0x0,0x0,                               // B 
0x353F63AD74319C04,0xF68AFDBF9B933998,0x28E05B3AAF153F82,0x3C67A5CB50A75BD, // Qxa 
0x23559C8A12B5637F,0x5B5051B1119E373B,0x278F3D149BAC8FAA,0x86C6D36FDAF0244, // Qxb 
0x8AB9CC634607E059,0x51430509C32A6440,0xBA739B657113D84,0x62039BE3E8F0691,  // Qya 
0xC51DD369F21FF550,0xE12AC7E5BA650CC3,0x3861D7D21AE532BD,0xAB7E3D96F16C979, // Qyb 
0xE17DE6C06F2A6DE9,0x850974924D3F77C2,0xB6499B50A846953F,0x1B377619212E7C8C, // Fx 
0xC582193F90D5922A,0xDC178B6DB2C08850,0x3EAB22F57B96AC8,0x9EBEE691ED18375};

#endif

#if MIRACL==32

const mr_small mprom[]={
0x1,0x40800000,0x0,0x0,0x0,0x0,0x0,0x80000000,
0x2,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0x74319C04,0x353F63AD,0x9B933998,0xF68AFDBF,0xAF153F82,0x28E05B3A,0xB50A75BD,0x3C67A5C,
0x12B5637F,0x23559C8A,0x119E373B,0x5B5051B1,0x9BAC8FAA,0x278F3D14,0xFDAF0244,0x86C6D36,
0x4607E059,0x8AB9CC63,0xC32A6440,0x51430509,0x57113D84,0xBA739B6,0x3E8F0691,0x62039BE,
0xF21FF550,0xC51DD369,0xBA650CC3,0xE12AC7E5,0x1AE532BD,0x3861D7D2,0x6F16C979,0xAB7E3D9,
0x6F2A6DE9,0xE17DE6C0,0x4D3F77C2,0x85097492,0xA846953F,0xB6499B50,0x212E7C8C,0x1B377619,
0x90D5922A,0xC582193F,0xB2C08850,0xDC178B6D,0x57B96AC8,0x3EAB22F,0x1ED18375,0x9EBEE69};

#endif
*/

#if MIRACL==64

const mr_small mprom[]={
0x4000000003C012B1,0x0,0x0,0x8000000000000000,
0x2,0x0,0x0,0x0,
0xC0851CEEE4D2EC74,0x907C85BFA03E2726,0x358B2500F5C34BBB,0x19682D2C7053B256,
0x47A58E8B2E29CFE1,0xF81B97B0C209C30F,0xA011C937A8E99743,0x1466B9EC3E19F64A,
0xCFBFCEBCF0BE09F,0x6361B33D847EC1B3,0xD81E22157DAEE209,0xA79EDD972332B8D,
0xED904B228898EE9D,0xC2864EA569D2EDEB,0x35C6E4512D8D3461,0x6160C39ECC4C090,
0x5BD9083355C80EA3,0x68677326F173F821,0xAFE18B8AACA71898,0x1359082FA63A0164,
0x628D1BBC06534710,0xBBD863C7269546C0,0xDC53D9CDBC4E3A,0x10A6F7D0623628A9};

#endif

#if MIRACL==32

const mr_small mprom[]={
0x3C012B1,0x40000000,0x0,0x0,0x0,0x0,0x0,0x80000000,
0x2,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
0xE4D2EC74,0xC0851CEE,0xA03E2726,0x907C85BF,0xF5C34BBB,0x358B2500,0x7053B256,0x19682D2C,
0x2E29CFE1,0x47A58E8B,0xC209C30F,0xF81B97B0,0xA8E99743,0xA011C937,0x3E19F64A,0x1466B9EC,
0xCF0BE09F,0xCFBFCEB,0x847EC1B3,0x6361B33D,0x7DAEE209,0xD81E2215,0x72332B8D,0xA79EDD9,
0x8898EE9D,0xED904B22,0x69D2EDEB,0xC2864EA5,0x2D8D3461,0x35C6E451,0xECC4C090,0x6160C39,
0x55C80EA3,0x5BD90833,0xF173F821,0x68677326,0xACA71898,0xAFE18B8A,0xA63A0164,0x1359082F,
0x6534710,0x628D1BBC,0x269546C0,0xBBD863C7,0xCDBC4E3A,0xDC53D9,0x623628A9,0x10A6F7D0};

#endif


static void start_hash(HASHFUNC *sha)
{
	SHS_INIT(sha);
}

static void add_to_hash(HASHFUNC *sha,octet *x)
{
	int i;
	for (i=0;i<x->len;i++) {/*printf("%d,",(unsigned char)x->val[i]);*/ SHS_PROCESS(sha,x->val[i]);  }
}

static void finish_hash(HASHFUNC *sha,octet *w)
{
	int i,hlen=HASH_BYTES;
	char hh[HASH_BYTES];
    SHS_HASH(sha,hh);
   
    OCTET_EMPTY(w);
    OCTET_JOIN_BYTES(hh,hlen,w);
    for (i=0;i<hlen;i++) hh[i]=0;
}

/*
void ecn_print(_MIPD_ epoint *P)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
	if (P->marker==MR_EPOINT_INFINITY)
	{
		printf("[Infinity]\n");
		return;
	}
	epoint_norm(_MIPP_ P);
	printf("["); 
	redc(_MIPP_ P->X,P->X);
	otstr(_MIPP_ P->X,mr_mip->IOBUFF);
	nres(_MIPP_ P->X,P->X);
	printf("%s,",mr_mip->IOBUFF);
	redc(_MIPP_ P->Y,P->Y);
	otstr(_MIPP_ P->Y,mr_mip->IOBUFF);
	nres(_MIPP_ P->Y,P->Y);
	printf("%s]\n",mr_mip->IOBUFF);
}

void zzn2_print(_MIPD_ zzn2 *x)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
	printf("("); 
	redc(_MIPP_ x->a,x->a);
	otstr(_MIPP_ x->a,mr_mip->IOBUFF); 
	nres(_MIPP_ x->a,x->a);
	printf("%s,",mr_mip->IOBUFF); 
	redc(_MIPP_ x->b,x->b);
	otstr(_MIPP_ x->b,mr_mip->IOBUFF); 
	nres(_MIPP_ x->b,x->b);
	printf("%s)",mr_mip->IOBUFF);
}

void zzn4_print(_MIPD_ zzn4 *x)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
	printf("("); zzn2_print(_MIPP_ &(x->a)); printf(","); zzn2_print(_MIPP_ &(x->b));  printf(")");
}

void zzn12_print(_MIPD_ zzn12 *x)
{
#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
#endif
	printf("("); zzn4_print(_MIPP_ &(x->a)); printf(","); zzn4_print(_MIPP_ &(x->b)); printf(","); zzn4_print(_MIPP_ &(x->c)); printf(")"); printf("\n");
}

void ecn2_print(_MIPD_ ecn2 *P)
{
	#ifdef MR_OS_THREADS
    miracl *mr_mip=get_mip();
	#endif
	if (P->marker==MR_EPOINT_INFINITY)
	{
		printf("[Infinity]\n");
		return;
	}
	ecn2_norm(_MIPP_ P);
	printf("[");
	zzn2_print(_MIPP_ &(P->x));
	printf(",");
	zzn2_print(_MIPP_ &(P->y));
	printf("]\n");
}
*/


/* Initialise the MPIN_BN domain structure
 * It is assumed that the EC domain details are obtained from ROM
 */

#define MR_MPIN_BN_INIT_RESERVE 20

int MPIN_DOMAIN_INIT(mpin_domain *DOM,const void *rom)
{ /* get domain details from ROM     */
	int i,pt,num=0;
#ifdef MR_GENERIC_AND_STATIC
	miracl instance;
	miracl *mr_mip=mirsys(&instance,2*PFS,16);
#else
    miracl *mr_mip=mirsys(2*PFS,16);
#endif
    big x,q,r,a,b,beta,xx,yy;
	ecn2 Q;
	zzn2 f,qx,qy;
    int words,promptr,err,res=0;
#ifndef MR_STATIC
    char *mem=(char *)memalloc(_MIPP_ MR_MPIN_BN_INIT_RESERVE);
#else
    char mem[MR_BIG_RESERVE(MR_MPIN_BN_INIT_RESERVE)];
    memset(mem,0,MR_BIG_RESERVE(MR_MPIN_BN_INIT_RESERVE));
#endif
	DOM->nibbles=2*PFS;
	words=MR_ROUNDUP(PFS*8,MIRACL);

	if (mr_mip==NULL || mem==NULL) res= MPIN_OUT_OF_MEMORY;

    mr_mip->ERCON=TRUE;

    if (res==0)
    {
        x=mirvar_mem(_MIPP_ mem, num++);
        q=mirvar_mem(_MIPP_ mem, num++);
        a=mirvar_mem(_MIPP_ mem, num++);
		b=mirvar_mem(_MIPP_ mem, num++);
        r=mirvar_mem(_MIPP_ mem, num++);
        xx=mirvar_mem(_MIPP_ mem, num++);
		yy=mirvar_mem(_MIPP_ mem, num++);
        beta=mirvar_mem(_MIPP_ mem, num++);
		ecn2_alloc(_MIPP_ &Q,mem,&num);
		zzn2_alloc(_MIPP_ &f,mem,&num);
		zzn2_alloc(_MIPP_ &qx,mem,&num);
		zzn2_alloc(_MIPP_ &qy,mem,&num);

/* read in from PROM and make simple integrity checks */

		promptr=0;
		init_big_from_rom(x,words,(const mr_small *)rom,words*ROM_SIZE,&promptr);  /* Read in BN parameter from ROM   */
		sftbit(_MIPP_ x,-(PFS*8-2),xx);  /* top 2 bits encode extra info */
		pt=size(xx);
		expb2(_MIPP_ (PFS*8-2),xx);
		divide(_MIPP_ x,xx,xx);

		mr_mip->TWIST=MR_SEXTIC_D;
		if ((pt&1)==1) mr_mip->TWIST=MR_SEXTIC_M;
		if ((pt&2)==2) negify(x,x); 

		init_big_from_rom(b,words,(const mr_small *)rom,words*ROM_SIZE,&promptr);  /* Read in curve parameter b from ROM   */

		getprb(_MIPP_ x,q,r,beta);
		zero(a);
		ecurve_init(_MIPP_ a,b,q,MR_PROJECTIVE);

		nres(_MIPP_ beta,beta);

		init_big_from_rom(xx,words,(const mr_small *)rom,words*ROM_SIZE,&promptr);
		init_big_from_rom(yy,words,(const mr_small *)rom,words*ROM_SIZE,&promptr);

		zzn2_from_bigs(_MIPP_ xx,yy,&qx);
		init_big_from_rom(xx,words,(const mr_small *)rom,words*ROM_SIZE,&promptr);
		init_big_from_rom(yy,words,(const mr_small *)rom,words*ROM_SIZE,&promptr);

		zzn2_from_bigs(_MIPP_ xx,yy,&qy);
		if (!ecn2_set(_MIPP_ &qx,&qy,&Q))  res=MR_ERR_BAD_PARAMETERS;
	}
	if (res==0)
	{	
		init_big_from_rom(xx,words,(const mr_small *)rom,words*ROM_SIZE,&promptr);
		init_big_from_rom(yy,words,(const mr_small *)rom,words*ROM_SIZE,&promptr);
		zzn2_from_bigs(_MIPP_ xx,yy,&f);
	}
	if (res==0)
	{
		DOM->flags=pt;
		big_to_bytes(_MIPP_ PFS,x,DOM->X,TRUE); /* bigs here */
		big_to_bytes(_MIPP_ PFS,q,DOM->Q,TRUE);
		big_to_bytes(_MIPP_ PFS,a,DOM->A,TRUE);
		big_to_bytes(_MIPP_ PFS,b,DOM->B,TRUE);
		big_to_bytes(_MIPP_ PGS,r,DOM->R,TRUE);
 		big_to_bytes(_MIPP_ PFS,beta,DOM->Beta,TRUE); /* nresidues from here */
		big_to_bytes(_MIPP_ PFS,qx.a,DOM->Qxa,TRUE); 
		big_to_bytes(_MIPP_ PFS,qx.b,DOM->Qxb,TRUE);
		big_to_bytes(_MIPP_ PFS,qy.a,DOM->Qya,TRUE);
		big_to_bytes(_MIPP_ PFS,qy.b,DOM->Qyb,TRUE);
		big_to_bytes(_MIPP_ PFS,f.a,DOM->Fa,TRUE);
		big_to_bytes(_MIPP_ PFS,f.b,DOM->Fb,TRUE);
	}

#ifndef MR_STATIC
    memkill(_MIPP_ mem,MR_MPIN_BN_INIT_RESERVE);
#else
    memset(mem,0,MR_BIG_RESERVE(MR_MPIN_BN_INIT_RESERVE));
#endif
    err=mr_mip->ERNUM;
    mirexit(_MIPPO_ );
    if (err==MR_ERR_OUT_OF_MEMORY) return MPIN_OUT_OF_MEMORY;
    if (err==MR_ERR_DIV_BY_ZERO) return MPIN_DIV_BY_ZERO;
    if (err!=0) return -(1000+err);
    return res;
}

void MPIN_DOMAIN_KILL(mpin_domain *DOM)
{
	int i;
	for (i=0;i<PFS;i++)
	{
		DOM->X[i]=0;
		DOM->Q[i]=0;
		DOM->A[i]=0;
		DOM->B[i]=0;
		DOM->Beta[i]=0;
		DOM->Qxa[i]=0;
		DOM->Qxb[i]=0;		
		DOM->Qya[i]=0;		
		DOM->Qyb[i]=0;	
		DOM->Fa[i]=0;
		DOM->Fb[i]=0;
	}
	for (i=0;i<PGS;i++)
		DOM->R[i]=0;
}



#define MR_MPIN_SERVER_RESERVE 38

int MPIN_SERVER(mpin_domain *DOM,int date,octet *CID,csprng *RNG,octet *Y,octet *W,octet *SST,octet *xCID,octet *mSEC,octet *AUTH,octet *K,octet *wCID,octet *E)
{
	int flags,num=0;
	HASHFUNC sha;
#ifdef MR_GENERIC_AND_STATIC
	miracl instance;
	miracl *mr_mip=mirsys(&instance,DOM->nibbles,16);
#else
	miracl *mr_mip=mirsys(DOM->nibbles,16);
#endif
    big x,q,a,b,r,beta,px,py,w,y;
	zzn2 f,qx,qy; 
	zzn4 c;
	zzn12 g; 
    ecn2 Q;
	epoint *P,*R;
    int err,res=0;
#ifndef MR_STATIC
    char *mem=(char *)memalloc(_MIPP_ MR_MPIN_SERVER_RESERVE);
	char *mem1=(char *)ecp_memalloc(_MIPP_ 2);
#else
    char mem[MR_BIG_RESERVE(MR_MPIN_SERVER_RESERVE)];    
	char mem1[MR_ECP_RESERVE(2)];
    memset(mem,0,MR_BIG_RESERVE(MR_MPIN_SERVER_RESERVE));
	memset(mem1,0,MR_ECP_RESERVE(2));
#endif
 
    if (mr_mip==NULL || mem==NULL || mem1==NULL) res= MPIN_OUT_OF_MEMORY;
    mr_mip->ERCON=TRUE;

    if (res==0)
    {
		x=mirvar_mem(_MIPP_ mem, num++);
        q=mirvar_mem(_MIPP_ mem, num++);
        a=mirvar_mem(_MIPP_ mem, num++);
        b=mirvar_mem(_MIPP_ mem, num++);
		r=mirvar_mem(_MIPP_ mem, num++);
		w=mirvar_mem(_MIPP_ mem, num++);
		y=mirvar_mem(_MIPP_ mem, num++);
        px=mirvar_mem(_MIPP_ mem, num++);
        py=mirvar_mem(_MIPP_ mem, num++);	
		beta=mirvar_mem(_MIPP_ mem, num++);  

		zzn2_alloc(_MIPP_ &qx,mem,&num);
		zzn2_alloc(_MIPP_ &qy,mem,&num);
		zzn2_alloc(_MIPP_ &f,mem,&num);
		ecn2_alloc(_MIPP_ &Q,mem,&num);
		zzn12_alloc(_MIPP_ &g,mem,&num);
		zzn4_alloc(_MIPP_ &c,mem,&num);

		flags=DOM->flags;

        bytes_to_big(_MIPP_ PFS,DOM->X,x);
		mr_mip->TWIST=MR_SEXTIC_D;
		if ((flags&1)==1) mr_mip->TWIST=MR_SEXTIC_M;
		if ((flags&2)==2) negify(x,x); 

        bytes_to_big(_MIPP_ PFS,DOM->Q,q);
        bytes_to_big(_MIPP_ PFS,DOM->A,a);
        bytes_to_big(_MIPP_ PFS,DOM->B,b);
		bytes_to_big(_MIPP_ PGS,DOM->R,r);
		bytes_to_big(_MIPP_ PFS,DOM->Beta,beta);
        bytes_to_big(_MIPP_ PFS,DOM->Fa,f.a);
        bytes_to_big(_MIPP_ PFS,DOM->Fb,f.b);

		if (RNG!=NULL)
		{
			strong_bigrand(_MIPP_ RNG,r,y);
			Y->len=big_to_bytes(_MIPP_ 0,y,Y->val,FALSE);
			strong_bigrand(_MIPP_ RNG,r,w);
			W->len=big_to_bytes(_MIPP_ 0,w,W->val,FALSE);
		}
		else
		{	
			bytes_to_big(_MIPP_ Y->len,Y->val,y);
			bytes_to_big(_MIPP_ W->len,W->val,w);
		}

        ecurve_init(_MIPP_ a,b,q,MR_PROJECTIVE);
 		P=epoint_init_mem(_MIPP_ mem1,0);
		R=epoint_init_mem(_MIPP_ mem1,1);
  
        bytes_to_big(_MIPP_ PFS,DOM->Qxa,qx.a);
        bytes_to_big(_MIPP_ PFS,DOM->Qxb,qx.b);
        bytes_to_big(_MIPP_ PFS,DOM->Qya,qy.a);
        bytes_to_big(_MIPP_ PFS,DOM->Qyb,qy.b);
    
		if (!ecn2_set(_MIPP_ &qx,&qy,&Q))  res=MR_ERR_BAD_PARAMETERS;
	}
	if (res==0)
	{

		hash(NULL,-1,CID,NULL,AUTH);	
		bytes_to_big(_MIPP_ AUTH->len,AUTH->val,px);
		divide(_MIPP_ px,q,q);
		while (!epoint_set(_MIPP_ px,px,0,P))
		{
			if (mr_mip->ERNUM!=0) break;
			incr(_MIPP_ px,1,px);
		}

		if (date)
		{
			hash(NULL,date,CID,NULL,AUTH);	/* H0(identity) plus H1(date|identity) */
			bytes_to_big(_MIPP_ AUTH->len,AUTH->val,px);
			divide(_MIPP_ px,q,q);
			while (!epoint_set(_MIPP_ px,px,0,R))
			{
				if (mr_mip->ERNUM!=0) break;
				incr(_MIPP_ px,1,px);
			}
			ecurve_add(_MIPP_ R,P);   // A+T
		}
	}
	if (res==0)
	{
	//	epoint_get(_MIPP_ P,px,py);
		G1_mult(_MIPP_ P,w,beta,r,x,R);  
		epoint_get(_MIPP_ R,px,py);

		wCID->len=2*PFS+1;	wCID->val[0]=4;
		big_to_bytes(_MIPP_ PFS,px,&(wCID->val[1]),TRUE);
		big_to_bytes(_MIPP_ PFS,py,&(wCID->val[PFS+1]),TRUE);  // Pg

		bytes_to_big(_MIPP_ PFS,&(mSEC->val[1]),px);
		bytes_to_big(_MIPP_ PFS,&(mSEC->val[PFS+1]),py);

		if (!epoint_set(_MIPP_ px,py,0,R)) res=MPIN_INVALID_POINT; //Px
	}
	if (res==0)
	{
		G1_mult(_MIPP_ R,y,beta,r,x,R);  

		rate_miller(_MIPP_ &Q,R,x,&f,&g);
        rate_fexp(_MIPP_ x,&f,&g);

/*		trace(_MIPP_ &g,&c);

		zzn12_copy(&g,&gp);
		zzn12_powq(_MIPP_ &f,&gp);

		trace(_MIPP_ &gp,&cp);

		zzn12_conj(_MIPP_ &g,&g);
		zzn12_mul(_MIPP_ &gp,&g,&gp);
		trace(_MIPP_ &gp,&cpm1);
		zzn12_mul(_MIPP_ &gp,&g,&gp);
		trace(_MIPP_ &gp,&cpm2);
*/
		E->len=12*PFS;
		
		redc(_MIPP_ g.a.a.a,a); big_to_bytes(_MIPP_ PFS,a,&(E->val[0]),TRUE);
		redc(_MIPP_ g.a.a.b,a); big_to_bytes(_MIPP_ PFS,a,&(E->val[PFS]),TRUE);
		redc(_MIPP_ g.a.b.a,a); big_to_bytes(_MIPP_ PFS,a,&(E->val[2*PFS]),TRUE);
		redc(_MIPP_ g.a.b.b,a); big_to_bytes(_MIPP_ PFS,a,&(E->val[3*PFS]),TRUE);

		redc(_MIPP_ g.b.a.a,a); big_to_bytes(_MIPP_ PFS,a,&(E->val[4*PFS]),TRUE);
		redc(_MIPP_ g.b.a.b,a); big_to_bytes(_MIPP_ PFS,a,&(E->val[5*PFS]),TRUE);
		redc(_MIPP_ g.b.b.a,a); big_to_bytes(_MIPP_ PFS,a,&(E->val[6*PFS]),TRUE);
		redc(_MIPP_ g.b.b.b,a); big_to_bytes(_MIPP_ PFS,a,&(E->val[7*PFS]),TRUE);

		redc(_MIPP_ g.c.a.a,a); big_to_bytes(_MIPP_ PFS,a,&(E->val[8*PFS]),TRUE);
		redc(_MIPP_ g.c.a.b,a); big_to_bytes(_MIPP_ PFS,a,&(E->val[9*PFS]),TRUE);
		redc(_MIPP_ g.c.b.a,a); big_to_bytes(_MIPP_ PFS,a,&(E->val[10*PFS]),TRUE);
		redc(_MIPP_ g.c.b.b,a); big_to_bytes(_MIPP_ PFS,a,&(E->val[11*PFS]),TRUE);

		bytes_to_big(_MIPP_ PFS,&(SST->val[0]),qx.a);
		bytes_to_big(_MIPP_ PFS,&(SST->val[PFS]),qx.b);
		bytes_to_big(_MIPP_ PFS,&(SST->val[2*PFS]),qy.a);
		bytes_to_big(_MIPP_ PFS,&(SST->val[3*PFS]),qy.b);
		nres(_MIPP_ qx.a,qx.a); nres(_MIPP_ qx.b,qx.b); nres(_MIPP_ qy.a,qy.a); nres(_MIPP_ qy.b,qy.b);

		if (!ecn2_set(_MIPP_ &qx,&qy,&Q))  res=MPIN_INVALID_POINT;
	}
	if (res==0)
	{
		bytes_to_big(_MIPP_ PFS,&(xCID->val[1]),px);
		bytes_to_big(_MIPP_ PFS,&(xCID->val[PFS+1]),py);

		if (!epoint_set(_MIPP_ px,py,0,R)) res=MPIN_INVALID_POINT; //Pa
	}
	if (res==0)
	{
		ecurve_add(_MIPP_ R,P);
		G1_mult(_MIPP_ P,y,beta,r,x,P);  

		rate_miller(_MIPP_ &Q,P,x,&f,&g);
        rate_fexp(_MIPP_ x,&f,&g);

		trace(_MIPP_ &g,&c);
		G1_mult(_MIPP_ R,w,beta,r,x,R);
		epoint_get(_MIPP_ R,px,py);

		AUTH->len=PFS;
		start_hash(&sha); 
		redc(_MIPP_ c.a.a,c.a.a); /*printf("e= "); otnum(_MIPP_ c.a.a,stdout); */ big_to_bytes(_MIPP_ PFS,c.a.a,&(AUTH->val[0]),TRUE);
		add_to_hash(&sha,AUTH);
		redc(_MIPP_ c.a.b,c.a.b); big_to_bytes(_MIPP_ PFS,c.a.b,&(AUTH->val[0]),TRUE);
		add_to_hash(&sha,AUTH);
		redc(_MIPP_ c.b.a,c.b.a); big_to_bytes(_MIPP_ PFS,c.b.a,&(AUTH->val[0]),TRUE);
		add_to_hash(&sha,AUTH);
		redc(_MIPP_ c.b.b,c.b.b); big_to_bytes(_MIPP_ PFS,c.b.b,&(AUTH->val[0]),TRUE);
		add_to_hash(&sha,AUTH);		

		big_to_bytes(_MIPP_ PFS,px,&(AUTH->val[0]),TRUE);
		add_to_hash(&sha,AUTH);	
		big_to_bytes(_MIPP_ PFS,py,&(AUTH->val[0]),TRUE);
		add_to_hash(&sha,AUTH);	
		finish_hash(&sha,AUTH);
	
		OCTET_EMPTY(K);
		OCTET_JOIN_BYTES(AUTH->val,PAS,K);

		start_hash(&sha);
		add_to_hash(&sha,K);
		add_to_hash(&sha,CID);
		add_to_hash(&sha,xCID);
		add_to_hash(&sha,mSEC);
		add_to_hash(&sha,wCID);

		finish_hash(&sha,AUTH);
	}

#ifndef MR_STATIC
    memkill(_MIPP_ mem,MR_MPIN_SERVER_RESERVE);
	ecp_memkill(_MIPP_ mem1,2);
#else
    memset(mem,0,MR_BIG_RESERVE(MR_MPIN_SERVER_RESERVE));
    memset(mem1,0,MR_ECP_RESERVE(2));
#endif
    err=mr_mip->ERNUM;
    mirexit(_MIPPO_ );
    if (err==MR_ERR_OUT_OF_MEMORY) return MPIN_OUT_OF_MEMORY;
    if (err==MR_ERR_DIV_BY_ZERO) return MPIN_DIV_BY_ZERO;
    if (err!=0) return -(1000+err);
    return res;
}




