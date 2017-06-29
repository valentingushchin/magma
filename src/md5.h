#ifndef MD5_H_
#define MD5_H_

#include <QByteArray>
#include <QString>
#include <QTextStream>

namespace vl {

//-----------------------------------//
class Md5
{
public:
        void md5Init();

        void md5Update(const quint8 *inBuf, quint32 inLen);

        template<typename T>
        void md5UpdateQ(const T &inArg);

        QString md5FinalStr();
        QByteArray md5FinalBin();

        QString getMd5Str(const quint8 *const buffer, quint32 length);
        QByteArray getMd5Bin(const quint8 *const buffer, quint32 length);

        template<typename T>
        QString getMd5QStr(const T &inArg);
        template<typename T>
        QByteArray getMd5QBin(const T &inArg);

private:
        const quint32 MD5_INIT_STATE_0 = 0x67452301;
        const quint32 MD5_INIT_STATE_1 = 0xefcdab89;
        const quint32 MD5_INIT_STATE_2 = 0x98badcfe;
        const quint32 MD5_INIT_STATE_3 = 0x10325476;

        quint8 padding[64] = {
                0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        quint8  buffer[64];
        quint32 count[2];
        quint32 md5[4];

        quint32 rotateLeft(quint32 x, int n) const;
        void quint32to8(quint32 *in, quint8 *out, int length) const;

        void f(quint32 &a, quint32 b, quint32 c, quint32 d, quint32 x, int s, quint32 ac) const;
        void g(quint32 &a, quint32 b, quint32 c, quint32 d, quint32 x, int s, quint32 ac) const;
        void h(quint32 &a, quint32 b, quint32 c, quint32 d, quint32 x, int s, quint32 ac) const;
        void i(quint32 &a, quint32 b, quint32 c, quint32 d, quint32 x, int s, quint32 ac) const;

        void transform(quint32 *buf, quint32 *in) const;
};
//-----------------------------------//

template<typename T>
void Md5::md5UpdateQ(const T &inArg)
{
        md5Update(reinterpret_cast<const quint8*>(inArg.data()), inArg.length());
}

template<typename T>
QString Md5::getMd5QStr(const T &inArg)
{
        md5Init();
        md5UpdateQ(inArg);
        return md5FinalStr();
}

template<typename T>
QByteArray Md5::getMd5QBin(const T &inArg)
{
        md5Init();
        md5UpdateQ(inArg);
        return md5FinalBin();
}

inline QString Md5::getMd5Str(const quint8 *const buffer, quint32 length)
{
        md5Init();
        md5Update(buffer, length);
        return md5FinalStr();
}

inline QByteArray Md5::getMd5Bin(const quint8 *const buffer, quint32 length)
{
        md5Init();
        md5Update(buffer, length);
        return md5FinalBin();
}

inline quint32 Md5::rotateLeft(quint32 x, int n) const
{
        return (x << n) | (x >> (32 - n));
}

inline void Md5::quint32to8(quint32 *in, quint8 *out, int length) const
{
        auto i = 0; auto j = 0;
        for (; j < length; i++, j += 4) {
                out[j]   = static_cast<quint8>( in[i]        & 0xff);
                out[j+1] = static_cast<quint8>((in[i] >>  8) & 0xff);
                out[j+2] = static_cast<quint8>((in[i] >> 16) & 0xff);
                out[j+3] = static_cast<quint8>((in[i] >> 24) & 0xff);
        }
}

inline void Md5::f(quint32 &a, quint32 b, quint32 c, quint32 d, quint32 x, int s, quint32 ac) const
{
        a += ((b & c) | (~b & d)) + x + ac;
        a = rotateLeft(a, s) + b;
}

inline void Md5::g(quint32 &a, quint32 b, quint32 c, quint32 d, quint32 x, int s, quint32 ac) const
{
        a += ((b & d) | (c & ~d)) + x + ac;
        a = rotateLeft(a, s) + b;
}

inline void Md5::h(quint32 &a, quint32 b, quint32 c, quint32 d, quint32 x, int s, quint32 ac) const
{
        a += (b ^ c ^ d) + x + ac;
        a = rotateLeft(a, s) + b;
}

inline void Md5::i(quint32 &a, quint32 b, quint32 c, quint32 d, quint32 x, int s, quint32 ac) const
{
        a += (c ^ (b | ~d)) + x + ac;
        a = rotateLeft(a, s) + b;
}

inline void Md5::transform(quint32 *buf, quint32 *in) const
{
        quint32 a = buf[0], b = buf[1], c = buf[2], d = buf[3];

        const auto S11=7;  const auto S12=12;
        const auto S13=17; const auto S14=22;

        f(a, b, c, d, in[ 0], S11, 0xD76AA478);
        f(d, a, b, c, in[ 1], S12, 0xE8C7B756);
        f(c, d, a, b, in[ 2], S13, 0x242070DB);
        f(b, c, d, a, in[ 3], S14, 0xC1BDCEEE);
        f(a, b, c, d, in[ 4], S11, 0xF57C0FAF);
        f(d, a, b, c, in[ 5], S12, 0x4787C62A);
        f(c, d, a, b, in[ 6], S13, 0xA8304613);
        f(b, c, d, a, in[ 7], S14, 0xFD469501);
        f(a, b, c, d, in[ 8], S11, 0x698098D8);
        f(d, a, b, c, in[ 9], S12, 0x8B44F7AF);
        f(c, d, a, b, in[10], S13, 0xffff5BB1);
        f(b, c, d, a, in[11], S14, 0x895CD7BE);
        f(a, b, c, d, in[12], S11, 0x6B901122);
        f(d, a, b, c, in[13], S12, 0xFD987193);
        f(c, d, a, b, in[14], S13, 0xA679438E);
        f(b, c, d, a, in[15], S14, 0x49B40821);

        const auto S21=5;  const auto S22=9;
        const auto S23=14; const auto S24=20;

        g(a, b, c, d, in[ 1], S21, 0xF61E2562);
        g(d, a, b, c, in[ 6], S22, 0xC040B340);
        g(c, d, a, b, in[11], S23, 0x265E5A51);
        g(b, c, d, a, in[ 0], S24, 0xE9B6C7AA);
        g(a, b, c, d, in[ 5], S21, 0xD62F105D);
        g(d, a, b, c, in[10], S22, 0x02441453);
        g(c, d, a, b, in[15], S23, 0xD8A1E681);
        g(b, c, d, a, in[ 4], S24, 0xE7D3FBC8);
        g(a, b, c, d, in[ 9], S21, 0x21E1CDE6);
        g(d, a, b, c, in[14], S22, 0xC33707D6);
        g(c, d, a, b, in[ 3], S23, 0xF4D50D87);
        g(b, c, d, a, in[ 8], S24, 0x455A14ED);
        g(a, b, c, d, in[13], S21, 0xA9E3E905);
        g(d, a, b, c, in[ 2], S22, 0xFCEFA3F8);
        g(c, d, a, b, in[ 7], S23, 0x676F02D9);
        g(b, c, d, a, in[12], S24, 0x8D2A4C8A);

        const auto S31=4;  const auto S32=11;
        const auto S33=16; const auto S34=23;

        h(a, b, c, d, in[ 5], S31, 0xffFA3942);
        h(d, a, b, c, in[ 8], S32, 0x8771F681);
        h(c, d, a, b, in[11], S33, 0x6D9D6122);
        h(b, c, d, a, in[14], S34, 0xFDE5380C);
        h(a, b, c, d, in[ 1], S31, 0xA4BEEA44);
        h(d, a, b, c, in[ 4], S32, 0x4BDECFA9);
        h(c, d, a, b, in[ 7], S33, 0xF6BB4B60);
        h(b, c, d, a, in[10], S34, 0xBEBFBC70);
        h(a, b, c, d, in[13], S31, 0x289B7EC6);
        h(d, a, b, c, in[ 0], S32, 0xEAA127FA);
        h(c, d, a, b, in[ 3], S33, 0xD4EF3085);
        h(b, c, d, a, in[ 6], S34, 0x04881D05);
        h(a, b, c, d, in[ 9], S31, 0xD9D4D039);
        h(d, a, b, c, in[12], S32, 0xE6DB99E5);
        h(c, d, a, b, in[15], S33, 0x1FA27CF8);
        h(b, c, d, a, in[ 2], S34, 0xC4AC5665);

        const auto S41=6;  const auto S42=10;
        const auto S43=15; const auto S44=21;

        i(a, b, c, d, in[ 0], S41, 0xF4292244);
        i(d, a, b, c, in[ 7], S42, 0x432Aff97);
        i(c, d, a, b, in[14], S43, 0xAB9423A7);
        i(b, c, d, a, in[ 5], S44, 0xFC93A039);
        i(a, b, c, d, in[12], S41, 0x655B59C3);
        i(d, a, b, c, in[ 3], S42, 0x8F0CCC92);
        i(c, d, a, b, in[10], S43, 0xffEff47D);
        i(b, c, d, a, in[ 1], S44, 0x85845DD1);
        i(a, b, c, d, in[ 8], S41, 0x6FA87E4F);
        i(d, a, b, c, in[15], S42, 0xFE2CE6E0);
        i(c, d, a, b, in[ 6], S43, 0xA3014314);
        i(b, c, d, a, in[13], S44, 0x4E0811A1);
        i(a, b, c, d, in[ 4], S41, 0xF7537E82);
        i(d, a, b, c, in[11], S42, 0xBD3AF235);
        i(c, d, a, b, in[ 2], S43, 0x2AD7D2BB);
        i(b, c, d, a, in[ 9], S44, 0xEB86D391);

        buf[0] += a; buf[1] += b;
        buf[2] += c; buf[3] += d;
}

} // end namespace vl

#endif // MD5_H_
