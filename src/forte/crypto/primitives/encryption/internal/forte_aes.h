//
// Created by cwood on 12/17/15.
//

#ifndef LIBFORTE_FORTE_AES_H
#define LIBFORTE_FORTE_AES_H


/**********************************************************************
 * Functions for key expansion
 *********************************************************************/

void ExpandKey (unsigned char Key[][4], unsigned char ExpandedKey[][4][4]);
void AddRoundKey (unsigned char Key[][4], unsigned char StateArray[][4]);

/**********************************************************************
 * Functions for AES encryption
 **********************************************************************/

void SubBytes (unsigned char StateArray[][4]);
void ShiftRows (unsigned char StateArray[][4]);
void MixColumns (unsigned char StateArray[][4]);

void SubBytesCalculated (unsigned char StateArray[][4]);

/**********************************************************************
 * Functions for AES decryption
 **********************************************************************/

void InvSubBytes (unsigned char StateArray[][4]);
void InvShiftRows (unsigned char StateArray[][4]);
void InvMixColumns (unsigned char StateArray[][4]);

/**********************************************************************
 * Miscellaneous Functions
 **********************************************************************/

void AES_printf (unsigned char StateArray[][4]);


#endif //LIBFORTE_FORTE_AES_H
