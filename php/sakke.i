/* sakke.i */
%module sakke
%{
/*! \brief Generate today's date for use in Time Permit generation */
extern int todaySAKKE(void);

/*! \brief Encapsulate the Shared Secret Value (SSV) */
extern int encapsulateSSV(char* SSV, char* ZS, int TPE, char* ID, int IDLength, char* HRbS);

/*! \brief Validate the Receiver Secret Key (RSK) */
extern int validateRSK(char* ZS, char* ID,  int IDLength, char* KbS);

/*! \brief Validate the time permit */
extern int validateSAKKETimePermit(int date, char* ID, int IDLength, char* ZS, char* KbS, char* TP);

/*! \brief Decapsulate the Shared Secret Value (SSV) */
extern int decapsulateSSV(char* HRbS, char* ZS, int TPE, char* ID, int IDLength, char* KbS, char* TP, char* SSV);
%}
/*! \brief Generate today's date for use in Time Permit generation */
extern int todaySAKKE(void);

/*! \brief Encapsulate the Shared Secret Value (SSV) */
extern int encapsulateSSV(char* SSV, char* ZS, int TPE, char* ID, int IDLength, char* HRbS);

/*! \brief Validate the Receiver Secret Key (RSK) */
extern int validateRSK(char* ZS, char* ID,  int IDLength, char* KbS);

/*! \brief Validate the time permit */
extern int validateSAKKETimePermit(int date, char* ID, int IDLength, char* ZS, char* KbS, char* TP);

/*! \brief Decapsulate the Shared Secret Value (SSV) */
extern int decapsulateSSV(char* HRbS, char* ZS, int TPE, char* ID, int IDLength, char* KbS, char* TP, char* SSV);
