//
//  main.cpp
//  test
//
//  Created by  hanchangxu on 2019/1/24.
//  Copyright © 2019年  hanchangxu. All rights reserved.
//

#include <iostream>
#include <string>
#include <fstream>
#include <exception>
#include <zlib.h>
#include <vector>
#include <stdio.h>
#include "uECC.h"

using namespace std;

const int MAGIC_NO_COMPRESS_START = 0x03;
const int MAGIC_NO_COMPRESS_START1 = 0x06;
const int MAGIC_NO_COMPRESS_NO_CRYPT_START = 0x08;
const int MAGIC_COMPRESS_START = 0x04;
const int MAGIC_COMPRESS_START1 = 0x05;
const int MAGIC_COMPRESS_START2 = 0x07;
const int MAGIC_COMPRESS_NO_CRYPT_START = 0x09;
const int MAGIC_END = 0x00;

extern int lastSeq;

//char* teaDecipher(char *v, char *k) {
//    int op = 0xffffffffL;
//    uint32_t v0=v[0], v1=v[1];
//    const static uint32_t delta=0x9e3779b9;
//    uint32_t k1=k[0], k2=k[1], k3=k[2], k4=k[3];
//    uint32_t s = (delta << 4) & op;
//    for (int i =0; i< 16; i++) {
//        v1 = (v1 - (((v0<<4) + k3) ^ (v0 + s) ^ ((v0>>5) + k4))) & op;
//        v0 = (v0 - (((v1<<4) + k1) ^ (v1 + s) ^ ((v1>>5) + k2))) & op;
//        s = (s - delta) & op;
//    }
//    v[0] = v0;
//    v[1] = v1;
//    return [1]char{' '};
//}
//
//
//char* teaDecrypt(char *v, char *k) {
//    int num = sizeof(v) / 8 * 8;
//    vector<char> ret;
//    for (int i = 0; i < num; i+= 8) {
//        uint8_t *tmp = new uint8_t[8];
//        for(int j =i; j < i+8; j++) {
//            tmp[j - i] = v[j];
//        }
//        teaDecipher(tmp, k);
//        ret.insert(ret.end(), tmp);
//    }
//    ret.insert(ret.end(), v + num, v + sizeof(v));
//    return reinterpret_cast<char*>(ret.data());
//}

void str_to_hex(char *string, char* cbuf, int len)
{
    int i;
    for (i=0; i<len; i++) {
        sprintf(cbuf+i*2, "%02x", string[i]);
    }
    cbuf[i*2] = 0;
}

//提取buffer中的部分char串
char* buffer(char* bufferChar, int offset, int length) {
    char* result = new char[length];
    for(int i = 0; i< length; i++) {
        result[i] = bufferChar[i + offset];
    }
    char output[length * 2 + 1];
    str_to_hex(result, output, length);
    return output;
}

int unpackNormal(char* bufferChar, int length) {
    cout << bufferChar;exit;
    if (sizeof(bufferChar) != length) return 0;
    int *a = new int[length]{1};
    for (int i = length - 2; i >= 0; i--) {
        a[i] = a[i + 1] * 16;
    }
    int result = 0;
    for(int i=0; i<length; i++) {
        int tmpInt;
        if (bufferChar[i] >= '0' && bufferChar[i] <= '9') {
            tmpInt = bufferChar[i] - '0';
        } else {
            tmpInt = bufferChar[i] - 'a' + 10;
        }
        result += a[i] * tmpInt;
    }
    exit(0);
    return result;
}

//将char串转化为整数，一般认为长度为4位
int unpackToInt(char* bufferChar) {
    int length = 8;
    int result = unpackNormal(bufferChar, length);
    return result;
}

char unpackToChar(char *bufferChar) {
    int length = 2;
    int result = unpackNormal(bufferChar, length);
    return char(result);
}

u_short unpackToUshort(char *bufferChar) {
    int length = 4;
    int result = unpackNormal(bufferChar, length);
    return u_short(result);
}

struct BufferResult {
    bool isGood;
    char *msg;

    BufferResult(bool isGood, char *msg){
        this->isGood = isGood;
        this->msg = msg;
    }
};

BufferResult IsGoodLogBuffer(char* bufferChar, int bufferLen, int offset, int count) {
    if (offset == bufferLen) return BufferResult(true, new char[0]);
    int magicStart = bufferChar[offset];
    int cryptKeyLen = 0;
    if (MAGIC_NO_COMPRESS_START==magicStart || MAGIC_COMPRESS_START==magicStart || MAGIC_COMPRESS_START1==magicStart){
        cryptKeyLen = 4;
    } else if (MAGIC_COMPRESS_START2==magicStart || MAGIC_NO_COMPRESS_START1==magicStart || MAGIC_NO_COMPRESS_NO_CRYPT_START==magicStart || MAGIC_COMPRESS_NO_CRYPT_START==magicStart) {
        cryptKeyLen = 64;
    } else {
        char *tmp = new char[30];
        sprintf(tmp, "_buffer[%d]:%d != MAGIC_NUM_START", offset, bufferChar[offset]);
        return BufferResult(false, tmp);
    }
    int headerLen = 1 + 2 + 1 + 1 + 4 + cryptKeyLen;
    if (offset + headerLen + 1 + 1 > bufferLen) {
        char *tmp = new char[30];
        sprintf(tmp, "offset:%d > len(buffer):%d", offset, bufferLen);
        return BufferResult(false, tmp);
    }
    uint32_t mm;
    memcpy(&mm, bufferChar + offset + headerLen - 4 - cryptKeyLen, 4);
    cout << mm;exit(0);
    int length = unpackToInt(buffer(bufferChar, offset+headerLen-4-cryptKeyLen, 4));
    cout << length;exit(0);
    if (offset + headerLen + length + 1 > bufferLen) {
        char *tmp = new char[30];;
        sprintf(tmp, "log length:%d, end pos %d > len(buffer):%d", length, offset + headerLen + length + 1, bufferLen);
        return BufferResult(false, tmp);
    }
    if (MAGIC_END != bufferChar[offset + headerLen + length]) {
        char *tmp = new char[30];
        sprintf(tmp, "log length:%d, buffer[%d]:%d != MAGIC_END", length, offset + headerLen + length, bufferChar[offset + length + headerLen]);
        return BufferResult(false, tmp);
    }
    if (count <= 1) return BufferResult(true, new char[0]);
    return IsGoodLogBuffer(bufferChar, bufferLen, offset+headerLen+length+1, count-1);
}

int getLogStartPos(char *bufferChar, int bufferLen, int count) {
    int offset = 0;
    while (true) {
        if (offset >= bufferLen) break;
        if (MAGIC_NO_COMPRESS_START==bufferChar[offset] || MAGIC_NO_COMPRESS_START1==bufferChar[offset] || MAGIC_COMPRESS_START==bufferChar[offset] || MAGIC_COMPRESS_START1==bufferChar[offset] || MAGIC_COMPRESS_START2==bufferChar[offset] || MAGIC_COMPRESS_NO_CRYPT_START==bufferChar[offset] || MAGIC_NO_COMPRESS_NO_CRYPT_START==bufferChar[offset]) {
            BufferResult result = IsGoodLogBuffer(bufferChar, bufferLen, offset, count);
            if (result.isGood){
                return offset;
            }
        }
        offset+=1;
    }
    return -1;
}
//
//bool __gzipUncompress(const char *src, int srcLen, std::vector<char> &output) {
//    z_stream stream;
//    stream.zalloc = Z_NULL;
//    stream.zfree = Z_NULL;
//    stream.avail_in = (uint)srcLen;
//    stream.next_in = (Bytef *)src;
//    stream.total_out = 0;
//    stream.avail_out = 0;
//
//    if (inflateInit2(&stream, 47) == Z_OK)
//    {
//        int status = Z_OK;
//        char outBuff[srcLen*2];
//        while (status == Z_OK)
//        {
//            stream.next_out = (uint8_t *)outBuff;
//            stream.avail_out = (uInt)sizeof(outBuff);
//            status = inflate (&stream, Z_SYNC_FLUSH);
//            output.insert(output.end(), outBuff, outBuff+(sizeof(outBuff)-stream.avail_out));
//            memset(outBuff, 0, sizeof(outBuff));
//        }
//        if (inflateEnd(&stream) == Z_OK)
//        {
//            if (status == Z_STREAM_END)
//            {
//                return true;
//            }
//        }
//    }
//    return false;
//}

//int decodeBuffer(char* bufferChar, int offset, std::vector<char> &outBuffer) {
//    if (offset >= sizeof(bufferChar)) return -1;
//    BufferResult ret = IsGoodLogBuffer(bufferChar, offset, 1);
//    int fixpos = 0;
//    if (!ret.isGood) {
//        fixpos = getLogStartPos(bufferChar, 1);
//        if (fixpos == -1) { return -1; }
//    } else {
//        //todo:
//        //_outbuffer.extend("[F]decode_log_file.py decode error len=%d, result:%s \n"%(fixpos, ret[1]))
//        char *tmp;
//        sprintf(tmp, "[F]decode_log_file.py decode error len=%d, result:%s \n", fixpos, ret.msg);
//        outBuffer.insert(outBuffer.end(), tmp, tmp+sizeof(tmp));
//        offset += fixpos;
//    }
//    char magicStart = bufferChar[offset];
//    int cryptKeyLen = 0;
//    if (MAGIC_NO_COMPRESS_START==magicStart || MAGIC_COMPRESS_START==magicStart || MAGIC_COMPRESS_START1==magicStart){
//        cryptKeyLen = 4;
//    } else if (MAGIC_COMPRESS_START2==magicStart || MAGIC_NO_COMPRESS_START1==magicStart || MAGIC_NO_COMPRESS_NO_CRYPT_START==magicStart || MAGIC_COMPRESS_NO_CRYPT_START==magicStart) {
//        cryptKeyLen = 64;
//    }
//    int headerLen = 1 + 2 + 1 + 1 + 4 + cryptKeyLen;
//    int length = unpackToInt(buffer(bufferChar, offset+headerLen-4-cryptKeyLen, 4));
//
//    u_short seq = unpackToUshort(buffer(bufferChar, offset+headerLen-4-cryptKeyLen-2-2, 2));
//    char beginHour = unpackToChar(buffer(bufferChar, offset+headerLen-4-cryptKeyLen-1-1, 1));
//    char endHour = unpackToChar(buffer(bufferChar, offset+headerLen-4-cryptKeyLen-1, 1));
//
//    if (seq != 0 && seq != 1 && lastSeq != 0 && seq != (lastSeq+1)){
//        char *tmp;
//        sprintf(tmp, "[F]decode_log_file.py log seq:%d-%d is missing\n", lastSeq+1, seq - 1);
//        outBuffer.insert(outBuffer.end(), tmp, tmp+sizeof(tmp));
//        if (seq != 0) {
//            lastSeq = seq;
//        }
//    }
//    char *tmpBuffer = new char[length];
//    memcpy(tmpBuffer, bufferChar + offset + headerLen, length);
//    vector<char> outputTmpBuffer;
//    try {
//        if (MAGIC_NO_COMPRESS_START1 == bufferChar[offset]) {}
//        else if (MAGIC_COMPRESS_START2 == bufferChar[offset]) {
//            char *publicKey = new char[cryptKeyLen];
//            memcpy(publicKey, bufferChar + offset + headerLen - cryptKeyLen, cryptKeyLen);
//            uint8_t server_pri[256] = "8d5526187969e9a6a9317e60a4a2f2ea7f5ebf200cae827fcb9f94bc83806511204d4bcc90240145cee7bf74a2603720ccd0b26a53d25cc0d5ccba05bb47cdac";
//            uint8_t ecdh_key[32] = {0};
//            uECC_shared_secret((uint8_t*)publicKey, server_pri, ecdh_key, uECC_secp256k1());
//            teaDecrypt(tmpBuffer, ecdh_key);
//            __gzipUncompress(tmpBuffer, length, outputTmpBuffer);
//        } else if (MAGIC_COMPRESS_START == bufferChar[offset] || MAGIC_COMPRESS_NO_CRYPT_START == bufferChar[offset]) {
//            __gzipUncompress(tmpBuffer, length, outputTmpBuffer);
//        } else if (MAGIC_COMPRESS_START1 == bufferChar[offset]) {
//            char* decompressData = new char[sizeof(tmpBuffer)];
//            while (sizeof(tmpBuffer) > 0){
//                u_short singleLogLen = unpackToUshort(buffer(tmpBuffer, 0, 2));
//                memcpy(decompressData, tmpBuffer + 2, singleLogLen);
//                if (sizeof(tmpBuffer) <= 2) break;
//                char* inTmp = new char[sizeof(tmpBuffer) - 2];
//                memcpy(inTmp, tmpBuffer + 2, sizeof(tmpBuffer) - 2);
//                tmpBuffer = inTmp;
//            }
//            __gzipUncompress(decompressData, length, outputTmpBuffer);
//        }
//    } catch (exception &e) {
//        char *tmp;
//        string errLog = e.what();
//        string tmpStr = "[F]decode_log_file.py decompress err, " + errLog + "\n";
//        tmp = (char*)tmpStr.data();
//        outBuffer.insert(outBuffer.end(), tmp, tmp + sizeof(tmp));
//        return offset+headerLen+length+1;
//    }
//    outBuffer.insert(outBuffer.end(), outputTmpBuffer.begin(), outputTmpBuffer.end());
//    return offset+headerLen+length+1;
//}

void parseFile(string inputPath, string outputPath) {
    ifstream iFile;
    iFile.open(inputPath, ios::in);
    if (!iFile.is_open()) return;
    iFile.seekg(0, iFile.end);
    size_t srcSize = iFile.tellg();
    if (!srcSize) return;
    //获取文件大小
    int size = int(srcSize);
    //生成缓存的char
    char bufferChar[size];
    //将文件存入到buffer中
    iFile.seekg(0,ios::beg);
    iFile.read(bufferChar, size);
    iFile.close();
    //用bufferChar生成结束的文件
    int startPos = getLogStartPos(bufferChar, int(sizeof(bufferChar)), 2);
//    //如果开始位置位-1.返回失败
//    if (startPos == -1) return;
//    //设置输出数组的动态数组
//    vector<char> outBuffer;
//    while (true){
////        startPos = decodeBuffer(bufferChar, startPos, outBuffer);
//        if (startPos == -1) break;
//    }
//    if (sizeof(outBuffer) == 0) return;
//    ofstream oFile;
//    oFile.open(outputPath);
//    char *printOutBuffer = outBuffer.data();
//    oFile.write(printOutBuffer, ios::out);
//    oFile.close();
}

int main(int argc, const char * argv[]) {
    parseFile("/tmp/in.log", "/tmp/out.log");
    return 0;
}
