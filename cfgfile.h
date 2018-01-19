#ifndef CFGFILE_H
#define CFGFILE_H

#include <QString>

class CfgFile
{

public:
    CfgFile(const QString &file);
    int encrypt(const QString &out_file);
    int decrypt(const QString &out_file);
    QString getFile() const;
    void setFile(const QString &file);

protected:
    // 01020304 return 04030201
    uint32_t order_adjustment(const uint32_t &value);

private:
    struct head {
        uint64_t magic;
        uint32_t uncompress_file_size;
        uint32_t compress_file_size;
        uint32_t compress_content_size;
        uint32_t compress_content_crc32;
        uint32_t head_block_crc32;
        uint32_t space[8];
    };
    struct data {
        uint32_t befor_compress_size;
        uint32_t after_compress_size;
        uint32_t pos_offset;
        uint8_t compress_content[0x10000];
    };
    QString file_;

    uint32_t get_crc32(const uint8_t *source, const size_t &size, const uint32_t &init_crc);
    void head_init(struct head &head_block);
    void head_change(struct head &head_block);

};

#endif // CFGFILE_H
