/* eccsi.i */
%module eccsi
%{
/*! \brief Generate today's date for use in Time Permit generation */
extern int todayECCSI(void);

/*! \brief Validate the Secret Signing Key (SSK) or the Time Permit (TP) */
extern int validateECCSIUserKey(int date, char* ID, int IDLength, char* KPAK, char* PVTSSK);

/*! \brief Sign a message */
extern int createSignature(int TPE, char* M, int MLength, char* ID,  int IDLength, char* KPAK,  
                           char* PVTSSK, char* TP, char* SIGNATURE, char* seedValue);

/*! \brief Verify the signature */
extern int verifySignature(int TPE, char* M, int MLength, char* ID, int IDLength, char* KPAK, 
                           char* SIGNATURE);
%}
/*! \brief Generate today's date for use in Time Permit generation */
extern int todayECCSI(void);

/*! \brief Validate the Secret Signing Key (SSK) or the Time Permit (TP) */
extern int validateECCSIUserKey(int date, char* ID, int IDLength, char* KPAK, char* PVTSSK);

/*! \brief Sign a message */
extern int createSignature(int TPE, char* M, int MLength, char* ID,  int IDLength, char* KPAK,  
                           char* PVTSSK, char* TP, char* SIGNATURE, char* seedValue);

/*! \brief Verify the signature */
extern int verifySignature(int TPE, char* M, int MLength, char* ID, int IDLength, char* KPAK, 
                           char* SIGNATURE);
