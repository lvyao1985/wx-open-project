# -*- coding: utf-8 -*-

import os
import hashlib
import base64

from Crypto.Cipher import AES


_KEY = hashlib.md5(os.getenv('AES_KEY_SEED')).hexdigest()
_MODE = AES.MODE_CBC
_IV = _KEY[:AES.block_size]


def encrypt(text):
    """
    AES加密 & BASE64编码
    :param text:
    :return:
    """
    cipher = AES.new(_KEY, _MODE, _IV)
    pad_amount = AES.block_size - len(text) % AES.block_size
    pad = chr(pad_amount)
    text += pad * pad_amount
    cipher_text = cipher.encrypt(text)
    return base64.b64encode(cipher_text)


def decrypt(text):
    """
    BASE64解码 & AES解密
    :param text:
    :return:
    """
    cipher = AES.new(_KEY, _MODE, _IV)
    cipher_text = base64.b64decode(text)
    plain_text = cipher.decrypt(cipher_text)
    pad = plain_text[-1]
    pad_amount = ord(pad)
    return plain_text[:-pad_amount]
