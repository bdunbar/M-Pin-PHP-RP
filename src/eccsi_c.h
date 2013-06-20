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
 *  MIRACL ECCSI header file
 *  Author: M. Scott 2012
 */

#ifndef ECCSI_H
#define ECCSI_H

#include "certivox.h"

#define EGS 32 /* ECCSI Group Size */
#define EFS 32 /* ECCSI Field Size */

#define ECCSI_OK                     0
#define ECCSI_DOMAIN_ERROR          -31
#define ECCSI_BAD_KEY		    -32
#define ECCSI_ERROR                 -33
#define ECCSI_INVALID_POINT         -34
#define ECCSI_DOMAIN_NOT_FOUND      -35
#define ECCSI_OUT_OF_MEMORY         -36
#define ECCSI_DIV_BY_ZERO           -37
#define ECCSI_BAD_SIG		    -38

#define PERMITS_ON 1
#define PERMITS_OFF 0

extern const mr_small esrom[];

/* ECp domain parameters */

typedef struct
{
	int nibbles;
    char Q[EFS];
    char A[EFS];
    char B[EFS];
    char R[EGS];
    char Gx[EFS];
    char Gy[EFS];
} ecs_domain;

/* ECCSI support functions */

extern void ECS_DOMAIN_KILL(ecs_domain *);
extern int  ECS_DOMAIN_INIT(ecs_domain *,const void *);

/* ECCSI primitives */
extern int  ECCSI_USER_KEY_VALIDATE(ecs_domain *,int,octet *,octet *,octet *);
extern int  ECCSI_SIGN(ecs_domain *,csprng *,octet*,octet *,octet *,octet *,octet *,octet *,octet *);
extern int  ECCSI_VERIFY(ecs_domain *,int,octet *,octet *,octet *,octet *);

#endif

