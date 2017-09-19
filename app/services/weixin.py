# -*- coding: utf-8 -*-

import base64
import hashlib
import socket
import struct
import time

from flask import current_app
from Crypto.Cipher import AES
import xmltodict

from utils.key_util import generate_random_key


class WXMsgCrypto(object):
    """
    微信消息加解密
    """
    aes_mode = AES.MODE_CBC
    block_size = 32

    def __init__(self, wx):
        """
        构造函数
        :param wx: [dict]
        """
        app_id, token, encoding_aes_key = map(wx.get, ('app_id', 'token', 'aes_key'))
        assert all((app_id, token, encoding_aes_key)), u'微信参数不完整'
        self.app_id = app_id
        self.token = token
        self.aes_key = base64.b64decode(encoding_aes_key + '=')
        assert len(self.aes_key) == 32, u'微信EncodingAESKey错误'
        self.aes_iv = self.aes_key[:16]

    def generate_sign(self, timestamp, nonce, msg_encrypt):
        """
        生成消息体签名
        :param timestamp:
        :param nonce:
        :param msg_encrypt:
        :return:
        """
        items = [self.token, timestamp, nonce, msg_encrypt]
        items.sort()
        return hashlib.sha1(''.join(items)).hexdigest()

    def encrypt(self, msg):
        """
        消息体加密并打包
        :param msg:
        :return:
        """
        plain_text = generate_random_key(16) + struct.pack('I', socket.htonl(len(msg))) + msg + self.app_id
        pad_amount = self.block_size - len(plain_text) % self.block_size
        pad = chr(pad_amount)
        plain_text += pad * pad_amount
        cipher = AES.new(self.aes_key, self.aes_mode, self.aes_iv)
        cipher_text = cipher.encrypt(plain_text)
        msg_encrypt = base64.b64encode(cipher_text)
        timestamp = str(int(time.time()))
        nonce = generate_random_key(16)
        msg_signature = self.generate_sign(timestamp, nonce, msg_encrypt)
        params = {
            'msg_encrypt': msg_encrypt,
            'msg_signature': msg_signature,
            'timestamp': timestamp,
            'nonce': nonce
        }
        return current_app.jinja_env.get_template('weixin/encrypted_msg.xml').render(**params)

    def decrypt(self, xml, msg_signature, timestamp, nonce):
        """
        消息体验证并解密
        :param xml:
        :param msg_signature:
        :param timestamp:
        :param nonce:
        :return:
        """
        msg_encrypt = xmltodict.parse(xml)['xml']['Encrypt']
        assert msg_signature == self.generate_sign(timestamp, nonce, msg_encrypt), u'微信消息体签名验证失败'
        cipher = AES.new(self.aes_key, self.aes_mode, self.aes_iv)
        cipher_text = base64.b64decode(msg_encrypt)
        plain_text = cipher.decrypt(cipher_text)
        pad = plain_text[-1]
        pad_amount = ord(pad)
        content = plain_text[16:-pad_amount]
        msg_len = socket.ntohl(struct.unpack('I', content[:4])[0])
        msg, app_id = content[4:msg_len + 4], content[msg_len + 4:]
        assert app_id == self.app_id, u'微信AppId验证失败'
        return xmltodict.parse(msg)['xml']
