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
/*! \file  mpinWrapper.c
    \brief Definitions for the MPIN algorithm wrappers

*-  Project     : MPin
*-  Authors     : Kealan McCusker
*-  Company     : Certivox
*-  Created     : 21/11/2012
*-  Last update : 28/01/2013
*-  Platform    : Linux (3.5)
*-  Dependency  : Miracl

    Provides an API for the MPIN algorithm

*/

/* #define DEBUG */
/* #define TEST */

#include "mpinWrapper.h"


/*! \brief Generate today's date for use in Time Permit generation
 *
 *  Generates todays date. Format is 24 bits: year (12 bits) | day_of_month (5 bits) | month (4 bits) | weekday (3 bits) 
 * 
 *  @return rtn   Returns todays date. Format is 24 bits: year (12 bits) | day_of_month (5 bits) | month (4 bits) | weekday (3 bits) 
 */
int todayMPin(void)
{
  int rtn=0;
  rtn = today();

#ifdef DEBUG
  printf("todayMPin: date: %d \n", rtn);
#endif

  return rtn;
}


/*! \brief Generate the server symmetric key
 *
 *  TODO update this text: The server calculates the Key and Authenticator by following these steps
 *
 *  <ol>
 *  <li> \f$ \pi_a=H_q(P_a|P_s|P_g), \pi_s=H_q(P_s|P_a|P_g) \f$ where \f$ H_q \f$ is a  hash
 *       function to a number in range 1 to q, \f$ P_a = xH_1(ID_c) \f$, 
 *       \f$ P_g = wH_1(ID_c) \f$ and \f$ P_s = yH_2(ID_s) \f$ 
 *  <li> Calculate the Tate pairing, \f$ k=e(\pi_a A+P_a,(y+\pi_s)sS) \f$
 *  <li> Calculate the Key, \f$ K=H(k|w{P_a}) \f$ where is a random number in range 1 to q
 *  <li> Calculate the authenticator \f$ M=H(ID_a|ID_s|K) \f$
 *  </ol>
 *  
 *  @param  TPE            Time permit enabled 1: Use Time Permits 0: Do not use Time Permits
 *  @param  date           Today's date
 *  @param  IDc            The client ID 
 *  @param  IDcLength      The length of the client ID in bytes
 *  @param  Y              Random number in range 1 to q
 *  @param  W              Random number in range 1 to q
 *  @param  serverSecret   The serverSecret. 
 *  @param  zIDc           \f$ P_a = z(H_1(ID_c)+T) \f$
 *  @param  maskedSecret   \f$ P_x = z(sH_1(ID_c)+sT) \f$
 *  @param  key            Return: The symmetric key
 *  @param  AUTHs          Return: The authenticator value
 *  @param  wIDc           Return: \f$ P_g = wH_1(ID_c) \f$
 *  @param  maskedPairing  Return: Masked Pairing
 *  @param  seedValue      100 byte random value
 *  @return rtn            Returns 0 if successful or else an error code  
 */
int calculateServerKey(int TPE, int date, char* IDc, int IDcLength, char* seedValue,
                       char* serverSecret, char* zIDc, char* maskedSecret, char* key, 
                       char* AUTHs, char* wIDc, char* maskedPairing, char* y, char* w)
{
  octet octetIDc={IDcLength,IDcLength,IDc};
  octet octetServerSecret={4*PFS,4*PFS,serverSecret};
  octet octetzIDc={2*PFS+1,2*PFS+1,zIDc};
  octet octetMaskedSecret={2*PFS+1,2*PFS+1,maskedSecret};
  octet octetKey={PAS,PAS,key};
  octet octetAUTHs={HASH_BYTES,HASH_BYTES,AUTHs};
  octet octetwIDc={2*PFS+1,2*PFS+1,wIDc};
  octet octetMaskedPairing ={12*PFS,12*PFS,maskedPairing};
  /* Y and W are used in TEST mode */
  octet octetY={PGS,PGS,y};
  octet octetW={PGS,PGS,w};


  mpin_domain mpdom;
  int rtn=0;

  /* Initialise elliptic curve from ROM */
  rtn = MPIN_DOMAIN_INIT(&mpdom,mprom);
  if (rtn != 0)
    {
      printf("Failed to initialize\n");
      return rtn; 
    }

  /* Crypto string RNG */
  csprng RNG;
  RNG = generateRNG(seedValue);

#ifdef TEST
  /* Do not use random values */
    rtn = MPIN_SERVER(&mpdom, date, &octetIDc, NULL, &octetY, &octetW,
                        &octetServerSecret,&octetzIDc,&octetMaskedSecret,
                        &octetAUTHs,&octetKey,&octetwIDc,&octetMaskedPairing);
#else
  if (TPE==1)
    rtn = MPIN_SERVER(&mpdom, date, &octetIDc, &RNG, &octetY, &octetW,
                        &octetServerSecret,&octetzIDc,&octetMaskedSecret,
                        &octetAUTHs,&octetKey,&octetwIDc,&octetMaskedPairing);
  else
    rtn = MPIN_SERVER(&mpdom, 0, &octetIDc, &RNG, &octetY, &octetW,
                        &octetServerSecret,&octetzIDc,&octetMaskedSecret,
                        &octetAUTHs,&octetKey,&octetwIDc,&octetMaskedPairing);
#endif

#ifdef DEBUG
  printf("calculateServerKey: TPE: %d\n", TPE);
  printf("calculateServerKey: date   := %d\n", date);
  printf("calculateServerKey: IDc   := 0x"); OCTET_OUTPUT(&octetIDc);
  printf("calculateServerKey: Y     := 0x"); OCTET_OUTPUT(&octetY);
  printf("calculateServerKey: W     := 0x"); OCTET_OUTPUT(&octetW);
  printf("calculateServerKey: ServerSecret := 0x"); OCTET_OUTPUT(&octetServerSecret);
  printf("calculateServerKey: zIDc  := 0x"); OCTET_OUTPUT(&octetzIDc);
  printf("calculateServerKey: maskedSecret  := 0x"); OCTET_OUTPUT(&octetMaskedSecret);
  printf("calculateServerKey: wIDc := 0x"); OCTET_OUTPUT(&octetwIDc);
  printf("calculateServerKey: maskedPairing := 0x"); OCTET_OUTPUT(&octetMaskedPairing);
  printf("calculateServerKey: AUTHs := 0x"); OCTET_OUTPUT(&octetAUTHs);
  printf("calculateServerKey: KEYs   := 0x"); OCTET_OUTPUT(&octetKey);
  printf("calculateServerKey: rtn: %d \n", rtn);
#endif

  MPIN_DOMAIN_KILL(&mpdom);

  return rtn;
}

































