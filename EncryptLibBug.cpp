#include <iostream>
#include <cstdint>
#include <cstring>

// Deklarasi kelas EncryptLib
class EncryptLib {
public:
    static int hexStringToDec(char Buffer[], int digit);
    static int hexCharToInt(char c);
    void EncryptHEX(const char Buffer[]);
};

// Array untuk referensi karakter dan enkripsi
const char Ref[71] = {'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5','6','7','8','9','{','}','<','>',':','[',']',',','\"'};
const uint8_t EncryptList[71] = {67, 58, 44, 39, 21, 16, 5, 63, 56, 41, 36, 29, 18, 4, 61, 54, 43, 31, 25, 13, 7, 66, 51, 42, 40, 22, 11, 1, 70, 52, 50, 34, 23, 14, 2, 62, 57, 45, 35, 30, 12, 3, 64, 55, 48, 32, 28, 17, 9, 68, 53, 47, 33, 24, 19, 8, 69, 59, 46, 37, 27, 15, 6, 65, 60, 49, 38, 26, 20, 10, 71};
const uint8_t SECURE_KEY_LENGTH = 10;
const char SECURE_KEY[SECURE_KEY_LENGTH + 1] = {'2','1','1','5','2','4','1','2','1','8'};
const uint8_t MAX_BUFFER_LENGTH = 160;
const uint8_t MAP_KEYS_NUM = 71;
const char END_MARKER = '\0';
const char HEX[] = "%02X";
char EncryptBuffer[MAX_BUFFER_LENGTH * 2 + 1];
uint8_t SecuredKeyPtr = 0;

// Deklarasi fungsi descryptTXT
void descryptTXT(char* buffer);

// Variabel descryptData
char descryptData[MAX_BUFFER_LENGTH + 1];

// Implementasi fungsi hexStringToDec
int EncryptLib::hexStringToDec(char Buffer[], int digit) {
    int intValue = 0;

    for (int c = 0; c < digit; c++) {
        int digitValue = hexCharToInt(Buffer[c]);

        if (digitValue == -1) return -1;

        intValue = (intValue << 4) | digitValue;
    }
    return intValue;
}

// Implementasi fungsi hexCharToInt
int EncryptLib::hexCharToInt(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

// Implementasi fungsi EncryptHEX
void EncryptLib::EncryptHEX(const char Buffer[]) {
    char intBuff[3];
    const uint8_t digit = 2;
    uint8_t indexDigit  = 0;
    uint8_t lastIndex   = 0;
    SecuredKeyPtr    = 0;

    for (uint8_t i = 0; i < MAX_BUFFER_LENGTH; i++) {
        char currentChar = Buffer[i];

        if (currentChar == 0) {
            lastIndex *= 2;
            EncryptBuffer[lastIndex++] = END_MARKER;
            EncryptBuffer[lastIndex] = 0;
            return;
        } else {
            for (uint8_t c = 0; c < MAP_KEYS_NUM; c++) {
                if (currentChar == Ref[c]) {
                    lastIndex++;
                    uint8_t xorEncrypt = SECURE_KEY[SecuredKeyPtr++] - '0';
                    sprintf(intBuff, HEX, (EncryptList[c] ^ xorEncrypt) << 1);
                    strncat(EncryptBuffer, intBuff, digit);
                    SecuredKeyPtr = SecuredKeyPtr == SECURE_KEY_LENGTH ? 0 : SecuredKeyPtr;
                    break;
                }
            }
        }
    }  
}

// Implementasi fungsi descryptTXT
void descryptTXT(char* buffer) {
    const uint8_t digit = 2;
    uint8_t indexDigit = 0;
    uint8_t lastIndex = 0;
    char intBuff[digit + 1];
    SecuredKeyPtr = 0;

    for (uint8_t i = 0; i < MAX_BUFFER_LENGTH; i++) {
        char currentChar = buffer[i];

        if (currentChar == '>') {
            descryptData[lastIndex] = 0;
            return;
        } else {
            intBuff[indexDigit] = currentChar;
            uint8_t xorEncrypt = SECURE_KEY[SecuredKeyPtr] - '0';

            if (++indexDigit == digit) {
                intBuff[indexDigit] = 0;
                SecuredKeyPtr = ++SecuredKeyPtr == SECURE_KEY_LENGTH ? 0 : SecuredKeyPtr;
    
                for (uint8_t c = 0; c < MAP_KEYS_NUM; c++) {
                    int convertedHexToInt = EncryptLib::hexStringToDec(intBuff, digit);
                    uint8_t currentNum = (convertedHexToInt >> 1) ^ xorEncrypt;
    
                    if (currentNum == EncryptList[c]) {
                        descryptData[lastIndex++] = Ref[c];
                    }
                }
                
                indexDigit = 0;
            }
        }
    }  
}

int main() {
    // Contoh penggunaan EncryptHEX
    char receiveData[MAX_BUFFER_LENGTH + 1] = "{\"data\":{\"id\":714491,\"newid\":491055,\"track\":0,\"req\":[\"pos\",\"card\",\"batt\"]}}";
    EncryptLib encryption;
    encryption.EncryptHEX(receiveData);
    std::cout << "Encrypted Data: " << EncryptBuffer << std::endl;

    // Deskripsi data
    char receiveData2[MAX_BUFFER_LENGTH + 1] = "044626460F474624074F3A264623271C44470E1008460510313C2645274D0D19203E390E460F1E4B2E254623230E461D142345271B42343918450B4F2E421E22450E463842050F46154443";
    descryptTXT(receiveData2);
    std::cout << "Decrypted Data: " << descryptData << std::endl;

    return 0;
}
