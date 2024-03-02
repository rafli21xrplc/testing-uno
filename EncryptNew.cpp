
#include <iostream>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

using namespace std;

#define SECURE_KEY_LENGTH  (10)
#define MAP_KEYS_NUM       (71)
#define MAX_BUFFER_LENGTH  (160)
#define END_MARKER  ';'
#define HEX "%02X"

const uint8_t EncryptMapKeys[MAP_KEYS_NUM]
{
    67, 58, 44, 39, 21, 16, 5,  63, 56, 41, 
    36, 29, 18, 4,  61, 54, 43, 31, 25, 13, 
    7,  66, 51, 42, 40, 22, 11, 1,  70, 52, 
    50, 34, 23, 14, 2,  62, 57, 45, 35, 30, 
    12, 3,  64, 55, 48, 32, 28, 17, 9,  68, 
    53, 47, 33, 24, 19, 8,  69, 59, 46, 37, 
    27, 15, 6,  65, 60, 49, 38, 26, 20, 10,
    71
};

const char CharRef[MAP_KEYS_NUM] = 
{
   'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
   'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
   '0','1','2','3','4','5','6','7','8','9',
   '{','}','<', '>',':','[',']',',','\"'
};


class EncryptLib
{
    private:
        int hexStringToDec(char Buffer[], uint8_t Digit);
        int hexCharToInt(char c);
        
        const char SecuredKey[SECURE_KEY_LENGTH + 1] = { '2','1','1','5','2','4','1','2','1','8' };
        uint8_t SecuredKeyPtr                     = 0;

    public:
        char EncryptBuffer[MAX_BUFFER_LENGTH + 1]        = {};
        char DescryptBuffer[MAX_BUFFER_LENGTH + 1]       = {};

        void EncryptHEX(const char Buffer[]);
        void DescryptHEX(const char Buffer[]);
};


void EncryptLib::EncryptHEX(const char Buffer[])
{
    char intBuff[3];
    const uint8_t digit = 2;
    uint8_t indexDigit  = 0;
    uint8_t lastIndex   = 0;
    SecuredKeyPtr    = 0;

    for (uint8_t i = 0; i < MAX_BUFFER_LENGTH; i++)
    {
        char currentChar = Buffer[i];

        if (currentChar == 0)
        {
            lastIndex *= 2;
            cout << "buffer size: " << lastIndex + 1 << endl;
            EncryptBuffer[lastIndex++] = END_MARKER;
            EncryptBuffer[lastIndex] = 0;
            return;
        }
        else
        {
            for (uint8_t c = 0; c < MAP_KEYS_NUM; c++)
            {
                if (currentChar == CharRef[c])
                {
                    lastIndex++;
                    uint8_t xorEncrypt = SecuredKey[SecuredKeyPtr++] - '0';
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
    const uint8_t digit = 2;
    uint8_t indexDigit  = 0;
    uint8_t lastIndex   = 0;
    SecuredKeyPtr    = 0;

    for (uint8_t i = 0; i < MAX_BUFFER_LENGTH; i++)
    {
        char currentChar = Buffer[i];

        if (currentChar == 0 || currentChar == END_MARKER)
        {
            DescryptBuffer[lastIndex] = 0;
            
            return;
        }
        else
        {
            hexBuff[indexDigit] = currentChar;

            if (++indexDigit == digit)
            {
                uint8_t xorEncrypt     = SecuredKey[SecuredKeyPtr++] - '0';
                hexBuff[indexDigit] = 0;
                indexDigit          = 0;
                SecuredKeyPtr = SecuredKeyPtr == SECURE_KEY_LENGTH ? 0 : SecuredKeyPtr;

                for (uint8_t c = 0; c < MAP_KEYS_NUM; c++)
                {
                    int convertedDec = hexStringToDec(hexBuff, digit);
                    uint8_t currentKey = (convertedDec >> 1) ^ xorEncrypt;

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

int EncryptLib::hexStringToDec(char Buffer[], uint8_t digit)
{
    int intValue = 0;

    for (uint8_t c = 0; c < digit; c++)
    {
        uint8_t digitValue = hexCharToInt(Buffer[c]);

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

char Data[MAX_BUFFER_LENGTH + 1] = "{\"data\":{\"id\":335018,\"newid\":140053,\"track\":0,\"req\":[\"pos\",\"card\",\"batt\"]}}";
//char Data[MAX_BUFFER_LENGTH + 1] = "08164C8C1E8E16660E04744C16681418744632262C160A2062784C1060208E40407C1420161E3C965C4A16684620163A284610604E1E687230102A045C843C4410201670840A1E16368886;";

void Print(const char Buffer[])
{
    cout.write("Print: ", 7);

    for (uint8_t c = 0; c < MAX_BUFFER_LENGTH; c++)
    {
        char currentChar = Buffer[c];
        if (currentChar == 0 || currentChar == END_MARKER) {
            cout.put('\n');
            break;
        }
        else {
            cout.put(currentChar);
        }
    }
}

EncryptLib Security;

int main()
{
    Security.EncryptHEX(Data);
    Print(Security.EncryptBuffer);
    Security.DescryptHEX(Security.EncryptBuffer);
    Print(Security.DescryptBuffer);

    //Security.DescryptHEX(Data);
    //Print(Security.DescryptBuffer);
    return 0;
}