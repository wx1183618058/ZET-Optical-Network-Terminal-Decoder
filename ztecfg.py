# -*- coding:utf-8 -*- #

from argparse import ArgumentParser, FileType
from binascii import crc32
from os.path import getsize
from struct import pack, unpack
from zlib import compress, decompress

from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def cfgFileAddSign(data, sign):
    print('cfgFileAddSign magic=0x%x sign=%s' % (0x04030201, sign))
    return pack('!III', 0x04030201, 0x0, len(sign)) + sign + data


def cfgFileDelSign(data):
    magic, _, size = unpack('!III', data[0:12])
    print('cfgFileDelSign magic=0x%x sign=%s' % (magic, data[12:12 + size]))
    return data[12 + size:]


def cfgFileAddVersion(data):
    print('cfgFileAddVersion magic=0x%x, 0x%x, 0x%x, 0x%x size=%s' % (0x99999999, 0x44444444, 0x55555555, 0xAAAAAAAA, len(data)))
    return pack('IIII8sI48sIIII36s', 0x99999999, 0x44444444, 0x55555555, 0xAAAAAAAA, b'', 0x4, b'', 0x50, 0x0, 0x80, len(data), b'') + data


def cfgFileDelVersion(data):
    magic1, magic2, magic3, magic4, _, _, _, _, _, _, size, _ = unpack('IIII8sI48sIIII36s', data[0:128])
    print('cfgFileDelVersion magic=0x%x, 0x%x, 0x%x, 0x%x size=%s' % (magic1, magic2, magic3, magic4, size))
    return data[128:]


def cfgFileEncryCRC(data):
    crc = 0x00000000
    offset = 60
    buffer = b''
    for i in range(0, len(data), 0x10000):
        block = data[i:i + 0x10000]
        comp_block = compress(block, 9)
        crc = crc32(comp_block, crc)
        offset = 0 if 0x10000+i >= len(data) else offset + 12 + len(comp_block)
        buffer += pack('!III', len(block), len(comp_block), offset)
        buffer += comp_block
        if not offset:
            print('cfgFileEncryCRC magic=0x%x size=0x%x comp_size=0x%x' % (0x01020304, len(data), len(buffer) + 60))
            header = pack('!IIIIII', 0x01020304, 0x0, len(data), len(buffer) + 60, 0x10000, crc)
            return header + pack('!I32s', crc32(header, 0x00000000), b'') + buffer


def cfgFileDecryCRC(data):
    magic, _, size, comp_size, _, _ = unpack('!IIIIII', data[0:24])
    print('cfgFileDecryCRC magic=0x%x size=0x%x comp_size=0x%x' % (magic, size, comp_size))
    offset = 60
    buffer = b''
    while True:
        _, size, next_offset = unpack('!III', data[offset:offset + 12])
        buffer += decompress(data[offset + 12:offset + 12 + size])
        offset = next_offset
        if not offset:
            return buffer


def cfgFileEncryAESCBC(data):
    key = SHA256.new(b'8cc72b05705d5c46f412af8cbed55aad'[0:31]).digest()
    iv = SHA256.new(b'667b02a85c61c786def4521b060265e8'[0:31]).digest()[0:16]
    aes = AES.new(key, AES.MODE_CBC, iv)
    offset = 60
    buffer = b''
    for i in range(0, len(data), 0x10000):
        block = data[i:i + 0x10000]
        aes_block = aes.encrypt(block + bytes(16 - len(block) % 16))
        offset = 0 if 0x10000+i >= len(data) else offset + 12 + len(aes_block)
        buffer += pack('!III', len(block), len(aes_block), offset)
        buffer += aes_block
        if not offset:
            print('cfgFileEncryAESCBC magic=0x%x sign=0x%x' % (0x01020304, 0x4))
            return pack('!II52s', 0x01020304, 0x4, b'') + buffer


def cfgFileDecryAESCBC(data):
    magic, sign, _ = unpack('II52s', data[0:60])
    print('cfgFileDecryAESCBC magic=0x%x sign=0x%x' % (magic, sign))
    key = b'8cc72b05705d5c46f412af8cbed55aad'[0:31] if 0x4000000 == sign else b'PON_Dkey'
    iv = b'667b02a85c61c786def4521b060265e8'[0:31] if 0x4000000 == sign else b'PON_DIV'
    key = SHA256.new(key).digest()
    iv = SHA256.new(iv).digest()[0:16]
    aes = AES.new(key, AES.MODE_CBC, iv)
    offset = 60
    buffer = b''
    while True:
        _, size, next_offset = unpack('!III', data[offset:offset + 12])
        buffer += aes.decrypt(data[offset + 12:offset + 12 + size])
        offset = next_offset
        if not offset:
            return buffer


def cfgFileEncryXOR(data):
    key = b'*&(*H65GFRUY6KH53%#74BUG^%^RFIOO*&*^&^RRU6YOK8PE(&(#TI_+7(U9(7!U(HF*(ET6FGHKDIO8E@67!R#@#'
    buffer = b''
    for i in range(len(data)):
        buffer += (data[i] ^ key[i % len(key)]).to_bytes(1, 'big')
    return buffer


def cfgFileDecryXOR(data):
    key = b'*&(*H65GFRUY6KH53%#74BUG^%^RFIOO*&*^&^RRU6YOK8PE(&(#TI_+7(U9(7!U(HF*(ET6FGHKDIO8E@67!R#@#'
    buffer = b''
    for i in range(len(data)):
        buffer += (data[i] ^ key[i % len(key)]).to_bytes(1, 'big')
    return buffer


if __name__ == '__main__':
    print('作者：欲断魂')
    print('介绍：仅支持中兴光猫3.0配置加解密')  
    parser = ArgumentParser()
    parser.add_argument('-i', required=True, type=FileType('rb'))
    parser.add_argument('-o', required=True, type=FileType('wb'))
    parser.add_argument('-s')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', choices=['CRC', 'AESCBC', 'XOR'])
    group.add_argument('-e', choices=['CRC', 'AESCBC', 'XOR'])
    args = parser.parse_args()
    if args.e:
        if 'CRC' == args.e:
            args.o.write(cfgFileEncryCRC(args.i.read()))
        elif 'AESCBC' == args.e:
            args.o.write(cfgFileEncryAESCBC(cfgFileEncryCRC(args.i.read())))
        elif 'XOR' == args.e:
            args.o.write(cfgFileAddVersion(cfgFileEncryXOR(cfgFileAddSign(cfgFileEncryCRC(args.i.read()), args.s.encode()))))
    elif args.d:
        if 'CRC' == args.d:
            args.o.write(cfgFileDecryCRC(args.i.read()))
        elif 'AESCBC' == args.d:
            args.o.write(cfgFileDecryCRC(cfgFileDecryAESCBC(args.i.read())))
        elif 'XOR' == args.d:
            args.o.write(cfgFileDecryCRC(cfgFileDelSign(cfgFileDecryXOR(cfgFileDelVersion(args.i.read())))))
