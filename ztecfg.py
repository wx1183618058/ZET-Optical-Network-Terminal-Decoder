# -*- coding:utf-8 -*- #

from binascii import crc32
from os.path import getsize
from struct import pack, unpack
from sys import argv
from zlib import compress, decompress

from Crypto.Cipher import AES
from Crypto.Hash import SHA256

if __name__ == '__main__':
    if 4 == len(argv) and '-d' == argv[1]:
        fin = open(argv[2], 'rb')
        fout = open(argv[3], 'wb')

        buffer = fin.read()
        magic, sign, _ = unpack('II52s', buffer[0:60])
        print('magic=0x%x, sign=0x%x' % (magic, sign))

        content = b''
        key = b'8cc72b05705d5c46f412af8cbed55aad'[0:31] if 0x4000000 == sign else b'PON_Dkey'
        iv = b'667b02a85c61c786def4521b060265e8'[0:31] if 0x4000000 == sign else b'PON_DIV'
        offset = 60
        while True:
            data_size, aes_data_size, next_offset = unpack('!III', buffer[offset:offset + 12])
            print('data_size=0x%x, aes_data_size=0x%x, offset=0x%x' % (data_size, aes_data_size, offset))
            content += AES.new(SHA256.new(key).digest(), AES.MODE_CBC, SHA256.new(iv).digest()[0:16]).decrypt(buffer[offset + 12:offset + 12 + aes_data_size])
            offset = next_offset
            if not offset:
                break

        magic, _, cfg_size, content_size, _, _, _, _ = unpack('IIIIIII32s', content[0:60])
        print('magic=0x%x, cfg_size=0x%x, content_size=0x%x' % (magic, cfg_size, content_size))
        
        offset = 60
        while True:
            data_size, comp_data_size, next_offset = unpack('!III', content[offset:offset + 12])
            print('data_size=0x%x, comp_data_size=0x%x, next_offset=0x%x' % (data_size, comp_data_size, next_offset))
            fout.write(decompress(content[offset + 12:offset + 12 + comp_data_size]))
            offset = next_offset
            if not offset:
                break
        fin.close()
        fout.close()
    elif 4 == len(argv) and '-e' == argv[1]:
        fin = open(argv[2], 'rb')
        fout = open(argv[3], 'wb')
        buffer = fin.read()
        
        content = b''
        crc = 0x00000000
        content_size = 60
        offset = 60
        for i in range(0, len(buffer), 0x10000):
            data = buffer[i:i + 0x10000]
            comp_data = compress(data, 9)
            crc = crc32(comp_data, crc)
            offset = offset + 12 + len(comp_data) if i + 0x10000 < len(buffer) else 0
            print('data_size=0x%x, comp_data_size=0x%x, next_offset=0x%x' % (len(data), len(comp_data), offset))
            content += pack('!III', len(data), len(comp_data), offset)
            content += comp_data
            if not offset:
                break
            content_size = content_size + 12 + len(comp_data)

        header = pack('!IIIIII', 0x01020304, 0, len(buffer), content_size, 0x10000, crc)
        print('magic=0x%x, cfg_size=0x%x, content_size=0x%x' % (0x01020304, len(buffer), content_size))
        buffer = header + pack('!I32s', crc32(header, 0x00000000), b'') + content
        fout.write(pack('!II52s', 0x01020304, 0x4, b''))
        print('magic=0x%x, sign=0x%x' % (0x4030201, 0x4000000))

        offset = 60
        for i in range(0, len(buffer), 0x10000):
            data = buffer[i:i + 0x10000]
            aes_data = AES.new(SHA256.new(b'8cc72b05705d5c46f412af8cbed55aad'[0:31]).digest(), AES.MODE_CBC, SHA256.new(b'667b02a85c61c786def4521b060265e8'[0:31]).digest()[0:16]).encrypt(data + bytes(16 - len(data) % 16))
            offset = offset + 12 + len(aes_data) if i + 0x10000 < len(buffer) else 0
            print('data_size=0x%x, aes_data_size=0x%x, offset=0x%x' % (len(data), len(aes_data), offset))
            fout.write(pack('!III', len(data), len(aes_data), offset))
            fout.write(aes_data)
            if not offset:
                break
        fin.close()
        fout.close()
    else:
        print('作者：欲断魂')
        print('简介：仅支持中兴光猫3.0配置加解密')
        print('ztecfg -d cipher.cfg plain.cfg')
        print('ztecfg -e plain.cfg cipher.cfg')
