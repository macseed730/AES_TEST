// AES_TEST.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <ctime>
#include "AES.h"


bool EncryptFile(char* srcFile, char* dstFile) {
    AES aes(AESKeyLength::AES_256);

    unsigned char key[] = "password";

    FILE* fp;
    fopen_s(&fp, srcFile, "rb");
    FILE* fq;
    fopen_s(&fq, dstFile, "wb");

    int readUnit = 32 * 100000;
    long fileSize, readSize, writtenBytes;

    if (fp != NULL && fq != NULL) {
        fseek(fp, 0, SEEK_END);
        fileSize = ftell(fp);

        fseek(fp, 0, SEEK_SET);
        fseek(fq, 0, SEEK_SET);

        unsigned char* plain = new unsigned char[readUnit + 1];
        unsigned char* out = new unsigned char[readUnit + 1];
        while (1) {
            readSize = fread(plain, sizeof(unsigned char), readUnit, fp);
            if (readSize != readUnit) break;
            out = aes.EncryptECB(plain, readSize, key);

            fseek(fq, 0, SEEK_END);
            writtenBytes = fwrite(out, sizeof(unsigned char), readSize, fq);
            if (writtenBytes != readSize) return false;
        }
        // process end part of this file
        if (readSize > 0 && readSize < readUnit) {
            int blocks = readSize / 32;
            int left = readSize - blocks * 32;

            out = aes.EncryptECB(plain, readSize - left, key);
            fseek(fq, 0, SEEK_END);
            writtenBytes = fwrite(out, sizeof(unsigned char), readSize - left, fq);

            if (writtenBytes != readSize - left) return false;

            if (left) {

                unsigned char* last = new unsigned char[65];
                int i;
                for (i = 0; i < left; i++)
                    last[i] = plain[readSize - left + i];
                for (i = left; i < 64; i++)
                    last[i] = 0;
                last[32] = left;

                unsigned char* outleft = aes.EncryptECB(last, 64, key);
                fseek(fq, 0, SEEK_END);
                writtenBytes = fwrite(outleft, sizeof(unsigned char), 64, fq);

                if (writtenBytes != 64) return false;

                delete[] outleft;
            }
        }
        delete[] plain;
        delete[] out;

        fclose(fp);
        fclose(fq);

        return true;
    }
    return false;
}


bool DecryptFile(char* srcFile, char* dstFile) {
    AES aes(AESKeyLength::AES_256);

    unsigned char key[] = "password";

    FILE* fp;
    fopen_s(&fp, srcFile, "rb");
    FILE* fq;
    fopen_s(&fq, dstFile, "wb");

    int readUnit = 32 * 100000;
    long fileSize, readSize, writtenBytes;

    if (fp != NULL && fq != NULL) {
        fseek(fp, 0, SEEK_END);
        fileSize = ftell(fp);

        fseek(fp, 0, SEEK_SET);
        fseek(fq, 0, SEEK_SET);

        unsigned char* cipher = new unsigned char[readUnit + 1];
        unsigned char* out = new unsigned char[readUnit + 1];
        int cnt = 0;
        int addedHistory[200] = { 0 };
        while (1) {
            readSize = fread(cipher, sizeof(unsigned char), readUnit, fp);
            if (readSize != readUnit) break;
            addedHistory[cnt++] = readSize;
            out = aes.DecryptECB(cipher, readSize, key);

            fseek(fq, 0, SEEK_END);
            writtenBytes = fwrite(out, sizeof(unsigned char), readSize, fq);
            if (writtenBytes != readSize) return false;
        }
        // process end part of this file
        if (readSize > 0 && readSize < readUnit) {
            int blocks = readSize / 32;
            int left = readSize - blocks * 32;

            if (left) {
                return false;
            }
            
            out = aes.DecryptECB(cipher, readSize, key);

            int oLeft = out[readSize - 32];

            fseek(fq, 0, SEEK_END);
            writtenBytes = fwrite(out, sizeof(unsigned char), readSize - (64 - oLeft), fq);

            if (writtenBytes != (readSize - (64 - oLeft))) return false;
        }
        delete[] cipher;
        delete[] out;

        fclose(fp);
        fclose(fq);

        return true;
    }
    return false;
}

int main()
{
    char srcFile[] = "2.pdf";
    char dstFile[] = "1.fdp";
    //EncryptFile(srcFile, dstFile);
    DecryptFile(dstFile, srcFile);
}