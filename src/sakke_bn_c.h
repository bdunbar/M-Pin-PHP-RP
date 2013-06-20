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
 *  MIRACL SAKKE header file
 *  Author: M. Scott 2012
 */

#ifndef SAKKE_H
#define SAKKE_H

#include "certivox.h"

// Define one of these..

#define BN_CURVE
//#define RFC_CURVE
//#define RFC_CURVE_V2

#define SAS 16  /* Symmetric Key size - 128 bits */

/* Field size is assumed to be greater than or equal to group size. MIRACL is initialised for big numbers of size SFS */

#ifdef BN_CURVE
#define SGS 32  /* SAKKE Group Size */
#define SFS 32  /* SAKKE Field Size */
#define G1S 2*SFS+1 /* Group 1 Size */
#define G2S 4*SFS   /* Group 2 Size */
#endif

#ifdef RFC_CURVE
#define SGS 128
#define SFS 128
#define G1S 2*SFS+1
#define G2S G1S
#endif

#ifdef RFC_CURVE_V2
#define SGS 32
#define SFS 128
#define G1S 2*SFS+1
#define G2S G1S
#endif

#define SAKKE_OK                     0
#define SAKKE_DOMAIN_ERROR          -21
#define SAKKE_INVALID_PUBLIC_KEY    -22
#define SAKKE_ERROR                 -23
#define SAKKE_INVALID_POINT         -24
#define SAKKE_DOMAIN_NOT_FOUND      -25
#define SAKKE_OUT_OF_MEMORY         -26
#define SAKKE_DIV_BY_ZERO           -27
#define SAKKE_BAD_KEY               -28

extern const mr_small skrom[];

/* SAKKE domain parameters */

typedef struct
{
	int nibbles;
	int flags;
    char Q[SFS];
    char A[SFS];
    char B[SFS];
    char R[SGS];
    char Px[SFS];
    char Py[SFS];
#ifdef BN_CURVE
	char X[SFS];
	char Beta[SFS];
	char Qxa[SFS];
	char Qxb[SFS];
	char Qya[SFS];
	char Qyb[SFS];
	char Fa[SFS];
	char Fb[SFS];
	char G[16][SFS];
#else
	char CF[SFS];
	char Sa[SFS];
	char Sb[SFS];
#endif
} sak_domain;

/* SAKKE support functions */

extern void SAKKE_DOMAIN_KILL(sak_domain *);
extern int  SAKKE_DOMAIN_INIT(sak_domain *,const void *);

/* SAKKE primitives */

extern int  SAKKE_KEY_ENCAPSULATE(sak_domain *,octet *,octet *,int,octet *,octet *);
extern int  SAKKE_KEY_DECAPSULATE(sak_domain *,octet *,octet *,octet *,octet *,octet *,octet *);
extern int  SAKKE_SECRET_KEY_VALIDATE(sak_domain *,octet *,octet *,octet *);
extern int  SAKKE_PERMIT_VALIDATE(sak_domain *,int,octet *,octet *,octet *,octet *);
extern mr_unsign32 SAKKE_GET_TIME_SLOT(octet *);

#endif

