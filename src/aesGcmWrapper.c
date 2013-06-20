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
/*! \file  aesGcmWrapper.c
    \brief Definitions for the AES GSM algorithm wrappers

*-  Project     : MPin
*-  Authors     : Kealan McCusker
*-  Company     : Certivox
*-  Created     : 04/12/2012
*-  Last update : 
*-  Platform    : Linux (3.5)
*-  Dependency  : Miracl

    Provides a wrapper around the Miracl AES GCM functions to aid the development
    of language extensions and a simple API in C.

*/

#include "aesGcmWrapper.h"

#define AS 16
#define IVLength 12

/*! \brief Encrypt data using AES GCM
 *
 *  AES is run as a block cypher in the GCM  mode of operation. The key size is 128 bits.
 *  This function will encrypt any data length.
 *
 *  @param  key           128 bit secret key
 *  @param  IV            96 bit initialization vector
 *  @param  header        Additional authenticated data (AAD). This data is authenticated, but not encrypted.
 *  @param  plaintext     Data to be encrypted
 *  @return ciphertext    Encrypted data. It is the same length as the plaintext.
 *  @return tag           128 bit authentication tag.
 *  @return rtn           Returns 0 if successful or else an error code  
 */
int aesGcmEncrypt(char* key, char* IV, char* header, int headerLength, 
                  char* plaintext, int plaintextLength, char* ciphertext, 
                  char* tag)
{
  gcm g;
  int keyLength=AS;
  int tagLength=AS;
  gcm_init(&g,keyLength,key,IVLength,IV);

  if(!gcm_add_header(&g,header,headerLength))
    {
      return AES_INIT_ERROR;
    }
  
  if(!gcm_add_cipher(&g,GCM_ENCRYPTING,plaintext,plaintextLength,ciphertext))
    {
      return AES_ENCRYPT_ERROR;
    }

  gcm_finish(&g,tag); 
  tagLength=16;
  return 0;
}

/*! \brief Decrypt data using AES GCM
 *
 *  AES is run as a block cypher in the GCM  mode of operation. The key size is 128 bits.
 *  This function will decrypt any data length.
 *
 *  @param  key           128 bit secret key
 *  @param  IV            96 bit initialization vector
 *  @param  header        Additional authenticated data (AAD). This data is authenticated, but not decrypted.
 *  @param  ciphertext    Encrypted data. 
 *  @return plaintext     Decrypted data. It is the same length as the ciphertext.
 *  @return tag           128 bit authentication tag.
 *  @return rtn           Returns 0 if successful or else an error code  
 */
int aesGcmDecrypt(char* key, char* IV, char* header, int headerLength, 
                  char* ciphertext, int ciphertextLength, char* plaintext, 
                  char* tag)
{
  gcm g;
  int keyLength=AS;
  int tagLength=AS;
  gcm_init(&g,keyLength,key,IVLength,IV);

  if(!gcm_add_header(&g,header,headerLength))
    {
      return AES_INIT_ERROR;
    }
  
  if(!gcm_add_cipher(&g,GCM_DECRYPTING,plaintext,ciphertextLength,ciphertext))
    {
      return AES_DECRYPT_ERROR;
    }

  gcm_finish(&g,tag); 
  tagLength=16;
  return 0;
}

/*! \brief Generate 128-bit AES Key
 *
 *  Generates a 128-bit AES key from random source 
 * 
 *  @param  seedValue  100 byte random value
 *  @return AESKEY     128-bit AES Key
 */
int generateAESKey(char* AESKEY, char* seedValue)
{
  octet octetAESKEY={AS,AS,AESKEY};
  int rtn=0;

  /* Crypto string RNG */
  csprng RNG;
  RNG = generateRNG(seedValue);

  AES_KEY(&RNG, &octetAESKEY);
  return rtn;
}

/*! \brief Generate 100 Byte Value that is used for random seeding
 *
 *  Generate 100 Byte Value that is used for random seeding 
 * 
 *  @return seedValue 100 byte random value
 */
int generateSeedValue(char* seedValue, int len)
{
  int rtn=0;
  int i=0;

  /* Crypto string RNG */
  csprng RNG;
  RNG = generateRNG(seedValue);

  for (i=0;i<len;i++)
    seedValue[i]=strong_rng(&RNG);

  return rtn;
}
