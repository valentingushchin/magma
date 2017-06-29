#ifndef CRYPT_H_
#define CRYPT_H_

#include <QString>
#include <QByteArray>

#include "md5.h"

namespace vl {

extern const QString dummyPass;

template <typename T>
struct isQString
{
        enum { result = false };
};

template <>
struct isQString<QString>
{
        enum { result = true };
};

template <typename T>
constexpr int elementSize(const T&)
{
        return (isQString<T>::result ? 2 : 1);
}

//-----------------------------------//
class crypt
{
public:
        void encrypt(quint32 const in[2], quint32 out[2]) const;
        void decrypt(quint32 const in[2], quint32 out[2]) const;

        template<typename T>
        bool encryptSimple(const T &inArg, QByteArray &outHash) const;

        template<typename T>
        bool decryptSimple(const QByteArray &inHash, T &outArg) const;

        template<typename T>
        bool encryptOFB(const T &inArg, QByteArray &outHash, const quint32 iv[2]) const;

        template<typename T>
        bool decryptOFB(const QByteArray &inHash, T &outArg, const quint32 iv[2]) const;

        template<typename T>
        bool encryptCFB(const T &inArg, QByteArray &outHash, quint32 iv[2]) const;

        template<typename T>
        bool decryptCFB(const QByteArray &inHash, T &outArg, quint32 iv[2]) const;

        template<typename T>
        bool encryptCFBSingle(const T &inArg, QByteArray &outHash) const;

        template<typename T>
        bool decryptCFBSingle(const QByteArray &inHash, T &outArg) const;

        template<typename T>
        quint32 mac(const T &arg, quint32 carry = 0) const;

        explicit crypt(const QString &pass = dummyPass);

        void loadKey(const QString &strKey);

private:
        quint32 key[8];

        quint8 k76[256];
        quint8 k54[256];
        quint8 k32[256];
        quint8 k10[256];

        const quint32 C1 = 0x01010104;
        const quint32 C2 = 0x01010101;

        quint32 f(quint32 x) const;

        void loadReplaceTable(const quint8 tbl[8][16]);

        void calcMac(const quint32 in[2], quint32 outMac[2]) const;
        void makeTail(const quint32 *const addrTail, quint32 tail[2], int lenTail) const;

        void splitStr(const QString &str, QString &left, QString &right) const;

};
//-----------------------------------//

inline quint32 crypt::f(quint32 x) const
{
        x = static_cast<quint32>(k76[ x        >> 24] << 24) |
            static_cast<quint32>(k54[(x << 8 ) >> 24] << 16) |
            static_cast<quint32>(k32[(x << 16) >> 24] << 8 ) |
            static_cast<quint32>(k10[(x << 24) >> 24]);

        return x<<11 | x>>21;
}

inline void crypt::encrypt(quint32 const in[2], quint32 out[2]) const
{
        quint32 n1 = in[0]; quint32 n2 = in[1];

        n2 ^= f(n1 + key[0]); n1 ^= f(n2 + key[1]);
        n2 ^= f(n1 + key[2]); n1 ^= f(n2 + key[3]);
        n2 ^= f(n1 + key[4]); n1 ^= f(n2 + key[5]);
        n2 ^= f(n1 + key[6]); n1 ^= f(n2 + key[7]);

        n2 ^= f(n1 + key[0]); n1 ^= f(n2 + key[1]);
        n2 ^= f(n1 + key[2]); n1 ^= f(n2 + key[3]);
        n2 ^= f(n1 + key[4]); n1 ^= f(n2 + key[5]);
        n2 ^= f(n1 + key[6]); n1 ^= f(n2 + key[7]);

        n2 ^= f(n1 + key[0]); n1 ^= f(n2 + key[1]);
        n2 ^= f(n1 + key[2]); n1 ^= f(n2 + key[3]);
        n2 ^= f(n1 + key[4]); n1 ^= f(n2 + key[5]);
        n2 ^= f(n1 + key[6]); n1 ^= f(n2 + key[7]);

        n2 ^= f(n1 + key[7]); n1 ^= f(n2 + key[6]);
        n2 ^= f(n1 + key[5]); n1 ^= f(n2 + key[4]);
        n2 ^= f(n1 + key[3]); n1 ^= f(n2 + key[2]);
        n2 ^= f(n1 + key[1]); n1 ^= f(n2 + key[0]);

        out[0] = n2; out[1] = n1;
}

inline void crypt::decrypt(quint32 const in[2], quint32 out[2]) const
{
        quint32 n1 = in[0]; quint32 n2 = in[1];

        n2 ^= f(n1 + key[0]); n1 ^= f(n2 + key[1]);
        n2 ^= f(n1 + key[2]); n1 ^= f(n2 + key[3]);
        n2 ^= f(n1 + key[4]); n1 ^= f(n2 + key[5]);
        n2 ^= f(n1 + key[6]); n1 ^= f(n2 + key[7]);

        n2 ^= f(n1 + key[7]); n1 ^= f(n2 + key[6]);
        n2 ^= f(n1 + key[5]); n1 ^= f(n2 + key[4]);
        n2 ^= f(n1 + key[3]); n1 ^= f(n2 + key[2]);
        n2 ^= f(n1 + key[1]); n1 ^= f(n2 + key[0]);

        n2 ^= f(n1 + key[7]); n1 ^= f(n2 + key[6]);
        n2 ^= f(n1 + key[5]); n1 ^= f(n2 + key[4]);
        n2 ^= f(n1 + key[3]); n1 ^= f(n2 + key[2]);
        n2 ^= f(n1 + key[1]); n1 ^= f(n2 + key[0]);

        n2 ^= f(n1 + key[7]); n1 ^= f(n2 + key[6]);
        n2 ^= f(n1 + key[5]); n1 ^= f(n2 + key[4]);
        n2 ^= f(n1 + key[3]); n1 ^= f(n2 + key[2]);
        n2 ^= f(n1 + key[1]); n1 ^= f(n2 + key[0]);

        out[0] = n2; out[1] = n1;
}

inline void crypt::calcMac(const quint32 in[2], quint32 outMac[2]) const
{
        quint32 n1 = outMac[0] ^ in[0];	quint32 n2 = in[1];

        n2 ^= f(n1 + key[0]); n1 ^= f(n2 + key[1]);
        n2 ^= f(n1 + key[2]); n1 ^= f(n2 + key[3]);
        n2 ^= f(n1 + key[4]); n1 ^= f(n2 + key[5]);
        n2 ^= f(n1 + key[6]); n1 ^= f(n2 + key[7]);

        n2 ^= f(n1 + key[0]); n1 ^= f(n2 + key[1]);
        n2 ^= f(n1 + key[2]); n1 ^= f(n2 + key[3]);
        n2 ^= f(n1 + key[4]); n1 ^= f(n2 + key[5]);
        n2 ^= f(n1 + key[6]); n1 ^= f(n2 + key[7]);

        outMac[0] = n1; outMac[1] = n2;
}

inline void crypt::makeTail(const quint32 *const addrTail, quint32 tail[2], int lenTail) const
{
        const quint8 *const half0 = reinterpret_cast<const quint8 *const>(addrTail);
        const quint8 *const half1 = reinterpret_cast<const quint8 *const>(addrTail + 1);

        tail[0] = tail[1] = 0;

        if (lenTail > 3) { // lenTail: 4..7
                tail[0] = addrTail[0];
        }

        else { // lenTail: 1..3
                for (auto i = 0; i < lenTail; ++i) {
                        tail[0] = tail[0] | static_cast<quint32>(*(half0 + i)) << (i << 3);
                }
        }

        if (lenTail > 4) { // lenTail: 5..7
                for (auto i = 0; i < lenTail - 4; ++i) {
                        tail[1] = tail[1] | static_cast<quint32>(*(half1 + i)) << (i << 3);
                }
        }
}

template<typename T>
bool crypt::encryptSimple(const T &inArg, QByteArray &outHash) const
{
        if(!inArg.length()) {
                return false;
        }

        const auto sizeInElements = elementSize(inArg);
        const auto len = inArg.length() * sizeInElements;
        const auto lenTail = len % 8;
        const auto lenSolid = len - lenTail;

        outHash.resize(lenSolid + (lenTail ? 8 : 0));

        const quint32 *const inData = reinterpret_cast<const quint32 *const>(inArg.data());
        quint32 *const outData = reinterpret_cast<quint32 *const>(outHash.data());

        if(lenSolid) {
                for(auto i = 0; i < (lenSolid >> 2); i += 2)
                        encrypt(inData + i, outData + i);
        }

        if(lenTail) {
                quint32 tail[2] = {0, 0};
                makeTail(inData + (lenSolid >> 2), tail, lenTail);
                encrypt(tail, outData + (lenSolid >> 2));
        }

        return true;
}

template<typename T>
bool crypt::decryptSimple(const QByteArray &inHash, T &outArg) const
{
        if(!inHash.length()) {
                return false;
        }

        const auto sizeOutElement = elementSize(outArg);
        const auto len = inHash.length();
        const auto lenTail = len % 8;

        if (lenTail) {
                return false;
        }

        outArg.resize(len / sizeOutElement);

        const quint32 *const inData = reinterpret_cast<const quint32 *const>(inHash.data());
        quint32 *const outData = reinterpret_cast<quint32 *const>(outArg.data());

        for(auto i = 0; i < (len >> 2); i += 2) {
                decrypt(inData + i, outData + i);
        }

        return true;
}

template<typename T>
bool crypt::encryptOFB(const T &inArg, QByteArray &outHash, const quint32 iv[2]) const
{
        if(!inArg.length()) {
                return false;
        }

        const auto sizeInElements = elementSize(inArg);
        const auto len = inArg.length() * sizeInElements;
        const auto lenTail = len % 8;
        const auto lenSolid = len - lenTail;

        outHash.resize(lenSolid + (lenTail ? 8 : 0));

        const quint32 *const inData = reinterpret_cast<const quint32 *const>(inArg.data());
        quint32 *const outData = reinterpret_cast<quint32 *const>(outHash.data());

        quint32 tmp[2];
        quint32 gamma[2];

        encrypt(iv, tmp);

        if(lenSolid) {
                for(auto i = 0; i < (lenSolid >> 2); i += 2) {
                        tmp[0] += C2;
                        if (tmp[0] < C2) {
                                tmp[0]++;
                        }

                        tmp[1] += C1;
                        if (tmp[1] < C1) {
                                tmp[1]++;
                        }

                        encrypt(tmp, gamma);

                        *(outData + i)     = *(inData  + i)     ^ gamma[0];
                        *(outData + i + 1) = *(inData  + i + 1) ^ gamma[1];
                }
        }

        if(lenTail) {
                quint32 tail[2] = {0, 0};

                makeTail(inData + (lenSolid >> 2), tail, lenTail);

                tmp[0] += C2;
                if (tmp[0] < C2) {
                        tmp[0]++;
                }

                tmp[1] += C1;
                if (tmp[1] < C1) {
                        tmp[1]++;
                }

                encrypt(tmp, gamma);

                *(outData + (lenSolid >> 2))     = tail[0] ^ gamma[0];
                *(outData + (lenSolid >> 2) + 1) = tail[1] ^ gamma[1];
        }

        outHash.resize(len);
        return true;
}

template<typename T>
bool crypt::decryptOFB(const QByteArray &inHash, T &outArg, const quint32 iv[2]) const
{
        if(!inHash.length()) {
                return false;
        }

        const auto sizeOutElement = elementSize(outArg);
        const auto len = inHash.length();
        const auto lenTail = len % 8;
        const auto lenSolid = len - lenTail;

        if (lenTail % sizeOutElement) {
                return false;
        }

        outArg.resize((lenSolid + (lenTail ? 8 : 0)) / sizeOutElement);

        const quint32 *const inData = reinterpret_cast<const quint32 *const>(inHash.data());
        quint32 *const outData = reinterpret_cast<quint32 *const>(outArg.data());

        quint32 tmp[2];
        quint32 gamma[2];

        encrypt(iv, tmp);

        if(lenSolid) {
                for(auto i = 0; i < (lenSolid >> 2); i += 2)
                {
                        tmp[0] += C2;
                        if (tmp[0] < C2) {
                                tmp[0]++;
                        }

                        tmp[1] += C1;
                        if (tmp[1] < C1) {
                                tmp[1]++;
                        }

                        encrypt(tmp, gamma);

                        *(outData + i)     = *(inData  + i) ^ gamma[0];
                        *(outData + i + 1) = *(inData  + i + 1) ^ gamma[1];
                }
        }

        if(lenTail) {
                quint32 tail[2] = {0, 0};
                makeTail(inData + (lenSolid >> 2), tail, lenTail);

                tmp[0] += C2;
                if (tmp[0] < C2) {
                        tmp[0]++;
                }

                tmp[1] += C1;
                if (tmp[1] < C1) {
                        tmp[1]++;
                }

                encrypt(tmp, gamma);

                *(outData + (lenSolid >> 2))     = tail[0] ^ gamma[0];
                *(outData + (lenSolid >> 2) + 1) = tail[1] ^ gamma[1];
        }

        outArg.resize(len / sizeOutElement);
        return true;
}

template<typename T>
bool crypt::encryptCFB(const T &inArg, QByteArray &outHash, quint32 iv[2]) const
{
        if(!inArg.length()) {
                false;
        }

        const auto sizeInElements = elementSize(inArg);
        const auto len = inArg.length() * sizeInElements;
        const auto lenTail = len % 8;
        const auto lenSolid = len - lenTail;

        outHash.resize(lenSolid + (lenTail ? 8 : 0));

        const quint32 *const inData = reinterpret_cast<const quint32 *const>(inArg.data());
        quint32 *const outData = reinterpret_cast<quint32 *const>(outHash.data());

        if(lenSolid) {
                for(auto i = 0; i < (lenSolid >> 2); i += 2) {
                        encrypt(iv, iv);

                        iv[0] = *(outData + i)     = *(inData  + i    ) ^ iv[0];
                        iv[1] = *(outData + i + 1) = *(inData  + i + 1) ^ iv[1];
                }
        }

        if(lenTail) {
                quint32 tail[2] = {0, 0};
                makeTail(inData + (lenSolid >> 2), tail, lenTail);

                encrypt(iv, iv);

                iv[0] = *(outData + (lenSolid >> 2))     = tail[0] ^ iv[0];
                iv[1] = *(outData + (lenSolid >> 2) + 1) = tail[1] ^ iv[1];
        }

        outHash.resize(len);

        return true;
}

template<typename T>
bool crypt::decryptCFB(const QByteArray &inHash, T &outArg, quint32 iv[2]) const
{
        if(!inHash.length()) {
                return false;
        }

        const auto sizeOutElement = elementSize(outArg);
        const auto len = inHash.length();
        const auto lenTail = len % 8;
        const auto lenSolid = len - lenTail;

        if (lenTail % sizeOutElement) {
                return false;
        }

        outArg.resize((lenSolid + (lenTail ? 8 : 0)) / sizeOutElement);

        const quint32 *const inData = reinterpret_cast<const quint32 *const>(inHash.data());
        quint32 *const outData = reinterpret_cast<quint32 *const>(outArg.data());

        quint32 t0 = 0, t1 = 0;

        if(lenSolid) {
                for(auto i = 0; i < (lenSolid >> 2); i += 2) {
                        encrypt(iv, iv);

                        t0 = *(inData  + i);
                        *(outData + i) = t0 ^ iv[0];
                        iv[0] = t0;

                        t1 = *(inData  + i + 1);
                        *(outData + i + 1) = t1 ^ iv[1];
                        iv[1] = t1;
                }
        }

        if(lenTail) {
                quint32 tail[2] = {0, 0};
                makeTail(inData + (lenSolid >> 2), tail, lenTail);

                encrypt(iv, iv);

                *(outData + (lenSolid >> 2))     = tail[0] ^ iv[0];
                *(outData + (lenSolid >> 2) + 1) = tail[1] ^ iv[1];
        }

        outArg.resize(len / sizeOutElement);

        return true;
}

template<typename T>
bool crypt::encryptCFBSingle(const T &inArg, QByteArray &outHash) const
{
        quint32 iv[2] = {0, 0};
        return encryptCFB(inArg, outHash, iv);
}

template<typename T>
bool crypt::decryptCFBSingle(const QByteArray &inHash, T &outArg) const
{
        quint32 iv[2] = {0, 0};
        return decryptCFB(inHash, outArg, iv);
}

template<typename T>
quint32 crypt::mac(const T &arg, quint32 carry) const
{
        if(!arg.length()) {
                return 0;
        }

        const auto argSize = elementSize(arg);
        const auto len = arg.length() * argSize;
        const auto lenTail = len % 8;
        const auto lenSolid = len - lenTail;

        quint32 outMac[2] = {carry, 0};

        const quint32 *const data = reinterpret_cast<const quint32 *const>(arg.data());

        if(lenSolid) {
                for(auto i = 0; i < (lenSolid >> 2); i += 2) {
                        calcMac(data + i, outMac);
                }
        }

        if(lenTail) {
                quint32 tail[2] = {0, 0};
                makeTail(data + (lenSolid >> 2), tail, lenTail);
                calcMac(tail, outMac);
        }

        return outMac[0];
}

} // end namespace vl

#endif // CRYPT_H_
