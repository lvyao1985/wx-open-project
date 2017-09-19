# -*- coding: utf-8 -*-

import socket

import ipgetter


def get_local_ip():
    """
    获取内网IP
    :return:
    """
    return socket.gethostbyname(socket.getfqdn())


def get_public_ip():
    """
    获取公网IP
    :return:
    """
    return ipgetter.myip()
