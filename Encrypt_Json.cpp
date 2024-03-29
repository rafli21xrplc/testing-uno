const char Ref[71] = 
{
   'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
   'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
   '0','1','2','3','4','5','6','7','8','9',
   '{','}','<','>',':','[',']',',','\"'
};

const uint8_t EncryptList[71] = 
{
    67, 58, 44, 39, 21, 16, 5,
    63, 56, 41, 36, 29, 18, 4,
    61, 54, 43, 31, 25, 13, 7,
    66, 51, 42, 40, 22, 11, 1,
    70, 52, 50, 34, 23, 14, 2,
    62, 57, 45, 35, 30, 12, 3,
    64, 55, 48, 32, 28, 17, 9,
    68, 53, 47, 33, 24, 19, 8,
    69, 59, 46, 37, 27, 15, 6,
    65, 60, 49, 38, 26, 20, 10,
    71                   
};

const byte SecureKeyLength = 10;
const char SecureKey[SecureKeyLength + 1] = { '2','1','1','5','2','4','1','2','1','8' };
const byte maxBufferLength = 160;
char descryptData[maxBufferLength + 1];
byte SecureKeyPtr = 0;

const char receiveData[maxBufferLength + 1] = "088C4C8C1E8E8C480E9E744C8C464E38888E1C20108C0A2062784C8A4E9A1A32407C721C8C3A28460A2830108A44368A386A5C84187A7E008C108C48823C4C8410867682180A2E3C52842C8A80>     ";

int main() 
{
  descryptTXT(receiveData);

  return 0;
}

void descryptTXT(char* buffer)
{
    const byte digit = 2;
    byte indexDigit = 0;
    byte lastIndex = 0;
    char intBuff[digit + 1];
    SecureKeyPtr = 0;

    for (byte i = 0; i < maxBufferLength; i++)
    {
        char currentChar = buffer[i];

        if (currentChar == '>')
        {
            descryptData[lastIndex] = 0;
            return;
        }
        else
        {
            intBuff[indexDigit] = currentChar;
            byte xorEncrypt = SecureKey[SecureKeyPtr] - '0';

            if (++indexDigit == digit)
            {
                intBuff[indexDigit] = 0;
                SecureKeyPtr = ++SecureKeyPtr == SecureKeyLength ? 0 : SecureKeyPtr;
    
                for (byte c = 0; c < 71; c++)
                {
                    int convertedHexToInt = hexStringToInt(intBuff, digit);
                    byte currentNum = (convertedHexToInt >> 1) ^ xorEncrypt;
    
                    if (currentNum == EncryptList[c])
                    {
                        descryptData[lastIndex++] = Ref[c];
                    }
                }
                
                indexDigit = 0;
            }
        }
    }  
}

int hexStringToInt(char* buffer, byte digit)
{
    byte intValue = 0;
    
    for (byte c = 0; c < digit; c++)
    {
        byte digitValue = hexCharToInt(buffer[c]);

        if (digitValue == - 1) return -1;

        intValue = (intValue << 4) | digitValue;
    }

    return intValue;
}

int hexCharToInt(char c) 
{
    if (c >= '0' && c <= '9') {
      return c - '0';
    } else if (c >= 'A' && c <= 'F') {
      return c - 'A' + 10;
    }
    return -1;
}
