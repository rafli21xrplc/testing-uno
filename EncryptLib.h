#ifndef EncryptLib_h
#define EncryptLib_h

#include "Arduino.h"
#include "Preferences.h"

Preferences EEPROM;

#define SECURE_KEY_LENGTH  (10)
#define MAP_KEYS_NUM       (70)
#define MAX_BUFFER_LENGTH  (160)
#define END_MARKER  ';'
#define HEX "%02X"

const byte EncryptMapKeys[MAP_KEYS_NUM]
{
    67, 58, 44, 39, 21, 16, 5,  63, 56, 41, 
    36, 29, 18, 4,  61, 54, 43, 31, 25, 13, 
    7,  66, 51, 42, 40, 22, 11, 1,  70, 52, 
    50, 34, 23, 14, 2,  62, 57, 45, 35, 30, 
    12, 3,  64, 55, 48, 32, 28, 17, 9,  68, 
    53, 47, 33, 24, 19, 8,  69, 59, 46, 37, 
    27, 15, 6,  65, 60, 49, 38, 26, 20, 10
};

const char CharRef[MAP_KEYS_NUM] = 
{
   'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
   'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
   '0','1','2','3','4','5','6','7','8','9',
   '{','}','<',':','[',']',',','\"'
};


class EncryptLib
{
    private:
        int hexStringToDec(char Buffer[], byte Digit);
        int hexCharToInt(char c);
        
        char SecuredKey[SECURE_KEY_LENGTH + 1] = {};
        byte SecuredKeyPtr                     = 0;
        //char SecureKey[SECURE_KEY_LENGTH + 1] = { '1','2','2','1','2','4','1','8','1','5' };

    public:
        char EncryptBuffer[MAX_BUFFER_LENGTH + 1]        = {};
        char DescryptBuffer[MAX_BUFFER_LENGTH + 1]       = {};

        void Init();
        void EncryptHEX(const char Buffer[]);
        void DescryptHEX(const char Buffer[]);
};


void EncryptLib::Init()
{
    EEPROM.begin("Guardian", false);
    EEPROM.getBytes("SecuredKey", SecuredKey, SECURE_KEY_LENGTH);

    #ifdef DEBUG_ENCRYPT
    Serial.begin(9600);

    for (byte i = 0; i < SECURE_KEY_LENGTH; i++)
    {
        Serial.print(SecuredKey[i]);
        Serial.print('\t');
    }
    Serial.println();
    #endif
}

void EncryptLib::EncryptHEX(const char Buffer[])
{
    char intBuff[3];
    const byte digit = 2;
    byte indexDigit  = 0;
    byte lastIndex   = 0;
    SecuredKeyPtr    = 0;

    for (byte i = 0; i < MAX_BUFFER_LENGTH; i++)
    {
        char currentChar = Buffer[i];

        if (currentChar == 0)
        {
            lastIndex *= 2;
            EncryptBuffer[lastIndex++] = END_MARKER;
            EncryptBuffer[lastIndex] = 0;
            return;
        }
        else
        {
            for (byte c = 0; c < MAP_KEYS_NUM; c++)
            {
                if (currentChar == CharRef[c])
                {
                    lastIndex++;
                    byte xorEncrypt = SecuredKey[SecuredKeyPtr++] - '0';
                    sprintf(intBuff, HEX, (EncryptMapKeys[c] ^ xorEncrypt) << 1);
                    strncat(EncryptBuffer, intBuff, digit);
                    SecuredKeyPtr = SecuredKeyPtr == SECURE_KEY_LENGTH ? 0 : SecuredKeyPtr;
                    break;
                }
            }
        }
    }  
}

void EncryptLib::DescryptHEX(const char Buffer[])
{
    char hexBuff[3];
    const byte digit = 2;
    byte indexDigit  = 0;
    byte lastIndex   = 0;
    SecuredKeyPtr    = 0;

    for (byte i = 0; i < MAX_BUFFER_LENGTH; i++)
    {
        char currentChar = Buffer[i];

        if (currentChar == 0 || currentChar == END_MARKER)
        {
            DescryptBuffer[lastIndex] = 0;
            Serial.println(lastIndex * 2 + 1);
            return;
        }
        else
        {
            hexBuff[indexDigit] = currentChar;

            if (++indexDigit == digit)
            {
                byte xorEncrypt     = SecuredKey[SecuredKeyPtr++] - '0';
                hexBuff[indexDigit] = 0;
                indexDigit          = 0;
                SecuredKeyPtr = SecuredKeyPtr == SECURE_KEY_LENGTH ? 0 : SecuredKeyPtr;

                for (byte c = 0; c < MAP_KEYS_NUM; c++)
                {
                    int convertedDec = hexStringToDec(hexBuff, digit);
                    byte currentKey = (convertedDec >> 1) ^ xorEncrypt;

                    if (currentKey == EncryptMapKeys[c])
                    {
                        DescryptBuffer[lastIndex++] = CharRef[c];
                        break;
                    }
                }
            }
        }
    }
}

int EncryptLib::hexStringToDec(char Buffer[], byte digit)
{
    int intValue = 0;

    for (byte c = 0; c < digit; c++)
    {
        byte digitValue = hexCharToInt(Buffer[c]);

        if (digitValue == - 1) return -1;

        intValue = (intValue << 4) | digitValue;
    }
    return intValue;
}

int EncryptLib::hexCharToInt(char c) 
{
    if (c >= '0' && c <= '9') {
      return c - '0';
    } else if (c >= 'A' && c <= 'F') {
      return c - 'A' + 10;
    }
    return -1;
}

#endif