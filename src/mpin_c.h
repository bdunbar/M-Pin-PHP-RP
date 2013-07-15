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
 *  MIRACL MPIN header file
 *  Author: M. Scott 2012
 */

#ifndef MPIN_H
#define MPIN_H

#include "certivox.h"

/* Field size is assumed to be greater than or equal to group size. MIRACL is initialised for big numbers of size PFS */

#define PGS 32  /* MPIN Group Size */
#define PFS 32  /* MPIN Field Size */
#define PAS 16  /* MPIN Symmetric Key Size */

#define MPIN_OK                     0
#define MPIN_DOMAIN_ERROR          -11
#define MPIN_INVALID_PUBLIC_KEY    -12
#define MPIN_ERROR                 -13
#define MPIN_INVALID_POINT         -14
#define MPIN_DOMAIN_NOT_FOUND      -15
#define MPIN_OUT_OF_MEMORY         -16
#define MPIN_DIV_BY_ZERO           -17
#define MPIN_WRONG_ORDER           -18
#define MPIN_BAD_PIN               -19

#define PINDIGITS 6

extern const mr_small mprom[];

/* M-Pin domain parameters */

typedef struct
{
	int nibbles;
	int flags;
	char X[PFS];
    char Q[PFS];
    char A[PFS];
    char B[PFS];
    char R[PGS];
	char Beta[PFS];
	char Qxa[PFS];
	char Qxb[PFS];
	char Qya[PFS];
	char Qyb[PFS];
	char Fa[PFS];
	char Fb[PFS];
} mpin_domain;

/* MPIN support functions */

extern void MPIN_DOMAIN_KILL(mpin_domain *);
extern int  MPIN_DOMAIN_INIT(mpin_domain *,const void *);

/* MPIN primitives */
extern int MPIN_SERVER(mpin_domain *,int,octet *,csprng *,octet *,octet *,octet *,octet *,octet *,octet *,octet *,octet *,octet *);
#endif

