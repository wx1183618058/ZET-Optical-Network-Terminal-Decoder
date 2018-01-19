#ifndef CTCE8CFGFILE_H
#define CTCE8CFGFILE_H

#include "cfgfile.h"
#include <QTemporaryFile>

class Ctce8CfgFile : public CfgFile
{
public:
    Ctce8CfgFile(const QString &filename);
    int encrypt(const QString &out_file, const QString &ver);
    int decrypt(const QString &out_file);

private:
    struct head_block {
        uint32_t magic_1[4];
        uint32_t empty_1[2];
        uint32_t sign_1;
        uint32_t empty_2[8];
        uint32_t sign_2;
        uint32_t sign_3[2];
        uint32_t filesize;
        uint32_t empty_3[13];
        uint32_t magic_2[2];
        uint32_t ver_size;
    };

    QTemporaryFile temp_file_;
};

#endif // CTCE8CFGFILE_H
