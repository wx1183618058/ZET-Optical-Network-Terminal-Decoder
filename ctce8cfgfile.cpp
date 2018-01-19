#include "ctce8cfgfile.h"
#include <QFile>

Ctce8CfgFile::Ctce8CfgFile(const QString &filename) : CfgFile(filename)
{
    temp_file_.open();
    QFile fin(filename);
    fin.open(QFile::ReadOnly);
    temp_file_.write(fin.readAll());
    fin.close();
    temp_file_.close();
    CfgFile::setFile(temp_file_.fileName());
}

int Ctce8CfgFile::encrypt(const QString &out_file, const QString &ver)
{
    QTemporaryFile temp_file_no_head;
    struct head_block head;

    temp_file_no_head.open();
    temp_file_no_head.close();
    CfgFile::encrypt(temp_file_no_head.fileName());

    memset(&head, 0, sizeof(head));
    head.magic_1[0] = 0x99999999;
    head.magic_1[1] = 0x44444444;
    head.magic_1[2] = 0x55555555;
    head.magic_1[3] = 0xaaaaaaaa;
    head.sign_1 = 0x4;
    head.sign_2 = 0x40;
    head.sign_3[0] = 0x2;
    head.sign_3[1] = 0x80;
    head.filesize = temp_file_no_head.size() + 22;
    head.magic_2[0] = 0x1020304;
    head.ver_size = order_adjustment(ver.size());
    QFile fout(out_file);
    if (!fout.open(QFile::WriteOnly)) return -1;
    if (!temp_file_no_head.open()) {
        fout.close();
        return -1;
    }
    fout.write((char*)&head, sizeof(head));
    fout.write(ver.toStdString().c_str());
    fout.write(temp_file_no_head.readAll());
    fout.close();
    temp_file_no_head.close();
    return 1;
}

int Ctce8CfgFile::decrypt(const QString &out_file)
{
    QTemporaryFile temp_file_no_head;

    struct head_block head;
    if (!temp_file_.open()) return -1;
    temp_file_.read((char*)&head, sizeof(head));
    if (head.magic_1[0] != 0x99999999 || head.magic_1[1] != 0x44444444 ||
            head.magic_1[2] != 0x55555555 || head.magic_1[3] != 0xaaaaaaaa ||
            head.filesize != temp_file_.size() - 128 || head.magic_2[0] != 0x1020304) {
        temp_file_.close();
        return -2;
    }
    if (!temp_file_no_head.open()) {
        temp_file_.close();
        return -1;
    }
    temp_file_.read(order_adjustment(head.ver_size));
    temp_file_no_head.write(temp_file_.readAll());
    temp_file_no_head.close();
    temp_file_.close();
    CfgFile::setFile(temp_file_no_head.fileName());
    return CfgFile::decrypt(out_file);
}
