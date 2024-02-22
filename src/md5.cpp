#include "md5.h"

namespace vl {

void Md5::md5Init()
{
        memset(buffer, 0, 64);
        count[0] = count[1] = 0;

        md5[0] = MD5_INIT_STATE_0;
        md5[1] = MD5_INIT_STATE_1;
        md5[2] = MD5_INIT_STATE_2;
        md5[3] = MD5_INIT_STATE_3;
}

void Md5::md5Update(const quint8 *inBuf, quint32 inLen)
{
        quint8 mdi = static_cast<quint8>(count[0] >> 3) & 0x3F;

        if ((count[0] + (inLen << 3)) < count[0]) {
                count[1]++;
        }

        count[0] += (inLen << 3);
        count[1] += (inLen >> 29);

        quint32 in[16];

        while (inLen--) {
                buffer[mdi++] = *inBuf++;

                if (mdi == 0x40) {

                        auto i = 0; auto ii = 0;
                        for (; i < 16; i++, ii += 4)
                                in[i] = (static_cast<quint32>(buffer[ii + 3]) << 24)        |
                                       ((static_cast<quint32>(buffer[ii + 2]) << 24) >>  8) |
                                       ((static_cast<quint32>(buffer[ii + 1]) << 24) >> 16) |
                                       ((static_cast<quint32>(buffer[ii + 0]) << 24) >> 24);

                        transform(md5, in);
                        mdi = 0;
                }
        }
}

QString Md5::md5FinalStr()
{
        quint8 bits[8];
        const auto md5Size = 16;
        quint8 md5[md5Size];

        quint32to8(count, bits, 8);

        quint8 index = static_cast<quint8>(count[0] >> 3) & 0x3f;

        quint32 padLen = (index < 56) ? (56 - index) : (120 - index);
        md5Update(padding, padLen);

        md5Update(bits, 8);

        quint32to8(Md5::md5, md5, md5Size);

        QString str = "", tmpStr = "";

        QTextStream stream(&tmpStr);
        stream.setIntegerBase(16);
        stream.setPadChar('0');
        stream.setFieldWidth(2);
        stream.setNumberFlags(QTextStream::UppercaseDigits);

        for (auto i=0; i < md5Size; ++i) {
                stream << md5[i];
                str += tmpStr;
                tmpStr.clear();
        }

        return str;
}

QByteArray Md5::md5FinalBin()
{
        quint8 bits[8];
        const auto md5Size = 16;
        quint8 md5[md5Size];

        quint32to8(count, bits, 8);

        quint8 index = static_cast<quint8>(count[0] >> 3) & 0x3f;

        quint32 padLen = (index < 56) ? (56 - index) : (120 - index);
        md5Update(padding, padLen);

        md5Update(bits, 8);

        quint32to8(Md5::md5, md5, md5Size);

        QByteArray bin;

        for (auto i=0; i < md5Size; ++i) {
                bin.append(static_cast<char>(md5[i]));
        }

        return bin;
}

} // end namespace vl
