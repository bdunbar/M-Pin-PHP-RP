/* aesGcm.i */
%module aesGcm
%{
  extern int aesGcmEncrypt(char* key, char* IV, char* header, int headerLength, char* plaintext, int plaintextLength, char* ciphertext, char* tag);
  extern int aesGcmDecrypt(char* key, char* IV, char* header, int headerLength, char* ciphertext, int ciphertextLength, char* plaintext, char* tag);
  extern void generateAESKey(char* AESKEY, char* seedValue);
  extern int generateSeedValue(char* seedValue, int len);
%}

  extern int aesGcmEncrypt(char* key, char* IV, char* header, int headerLength, char* plaintext, int plaintextLength, char* ciphertext, char* tag);
  extern int aesGcmDecrypt(char* key, char* IV, char* header, int headerLength, char* ciphertext, int ciphertextLength, char* plaintext, char* tag);
  extern void generateAESKey(char* AESKEY, char* seedValue);
  extern int generateSeedValue(char* seedValue, int len);
