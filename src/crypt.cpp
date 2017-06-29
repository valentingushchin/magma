#include "crypt.h"

namespace vl {
//                                       "<..><..><..><..>"
const QString dummyPass = QStringLiteral("_Dummy_Password_");

const quint8 table[8][16] = {
        {0x7, 0x4, 0x0, 0x5, 0xA, 0x2, 0xF, 0xE, 0xC, 0x6, 0x1, 0xB, 0xD, 0x9, 0x3, 0x8},
        {0xA, 0x9, 0x6, 0x8, 0xD, 0xE, 0x2, 0x0, 0xF, 0x3, 0x5, 0xB, 0x4, 0x1, 0xC, 0x7},
        {0xC, 0x9, 0xB, 0x1, 0x8, 0xE, 0x2, 0x4, 0x7, 0x3, 0x6, 0x5, 0xA, 0x0, 0xF, 0xD},
        {0x8, 0xD, 0xB, 0x0, 0x4, 0x5, 0x1, 0x2, 0x9, 0x3, 0xC, 0xE, 0x6, 0xF, 0xA, 0x7},
        {0x3, 0x6, 0x0, 0x1, 0x5, 0xD, 0xA, 0x8, 0xB, 0x2, 0x9, 0x7, 0xE, 0xF, 0xC, 0x4},
        {0x8, 0x2, 0x5, 0x0, 0x4, 0x9, 0xF, 0xA, 0x3, 0x7, 0xC, 0xD, 0x6, 0xE, 0x1, 0xB},
        {0x0, 0x1, 0x7, 0xD, 0xB, 0x4, 0x5, 0x2, 0x8, 0xE, 0xF, 0xC, 0x9, 0xA, 0x6, 0x3},
        {0x1, 0xB, 0xC, 0x2, 0x9, 0xD, 0x0, 0xF, 0x4, 0x5, 0x8, 0xE, 0xA, 0x7, 0x6, 0x3}
};

crypt::crypt(const QString &pass)
{
        loadKey(pass);
        loadReplaceTable(table);
}

void crypt::splitStr(const QString &str, QString &left, QString &right) const
{
        auto len = str.length();
        if (len == 0) {
                left =  " ";
                right = " ";
        } else
        if (len == 1) {
                left =  str;
                right = " ";
        } else {
                auto rightLen = len / 2;
                auto leftLen  = rightLen + len % 2;
                left  = str.left(leftLen);
                right = str.right(rightLen);
        }
}

void crypt::loadKey(const QString &strKey)
{
        QString str = strKey.trimmed();
        QString left =  "";
        QString right = "";

        splitStr(str, left, right);

        Md5 hash;
        QByteArray md5Bin = hash.getMd5QBin(left);
        md5Bin.append(hash.getMd5QBin(right));

        for (auto i = 0; i < 8; ++i) {
                auto ii = i << 2;
                key[i] =  (static_cast<quint32>(md5Bin[ii + 3]) << 24) |
                         ((static_cast<quint32>(md5Bin[ii + 2]) << 24) >> 8 ) |
                         ((static_cast<quint32>(md5Bin[ii + 1]) << 24) >> 16) |
                         ((static_cast<quint32>(md5Bin[ii + 0]) << 24) >> 24);
        }
}

void crypt::loadReplaceTable(const quint8 tbl[8][16])
{
        auto k = 0;
        for (auto i = 0; i < 16; ++i) {
                for (auto j = 0; j < 16; ++j) {
                        k10[k] = static_cast<quint8>(tbl[1][i] << 4) | tbl[0][j];
                        k32[k] = static_cast<quint8>(tbl[3][i] << 4) | tbl[2][j];
                        k54[k] = static_cast<quint8>(tbl[5][i] << 4) | tbl[4][j];
                        k76[k] = static_cast<quint8>(tbl[7][i] << 4) | tbl[6][j];
                        ++k;
                }
        }
}

} // end namespace vl
