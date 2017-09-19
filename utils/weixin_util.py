# -*- coding: utf-8 -*-

import os
import json

import requests

from .redis_util import redis_client


VERIFY = os.getenv('CA_CERTS_PATH') or False


def get_component_access_token(wx):
    """
    获取微信第三方平台component_access_token
    :param wx: [dict]
    :return:
    """
    app_id, app_secret = map(wx.get, ('app_id', 'app_secret'))
    verify_ticket = redis_client.get('wx:%s:component_verify_ticket' % app_id)
    if not all((app_id, app_secret, verify_ticket)):
        return

    key = 'wx:%s:component_access_token' % app_id
    access_token = redis_client.get(key)
    if access_token:
        return access_token

    wx_url = 'https://api.weixin.qq.com/cgi-bin/component/api_component_token'
    data = {
        'component_appid': app_id,
        'component_appsecret': app_secret,
        'component_verify_ticket': verify_ticket
    }
    resp_json = requests.post(wx_url, data=json.dumps(data, ensure_ascii=False), verify=VERIFY).json()
    access_token, expires_in = map(resp_json.get, ('component_access_token', 'expires_in'))
    if not (access_token and expires_in):
        return

    redis_client.set(key, access_token, ex=int(expires_in) - 600)  # 提前10分钟更新component_access_token
    return access_token


def get_pre_auth_code(wx):
    """
    获取微信第三方平台pre_auth_code
    :param wx: [dict]
    :return:
    """
    access_token = get_component_access_token(wx)
    if not access_token:
        return

    wx_url = 'https://api.weixin.qq.com/cgi-bin/component/api_create_preauthcode'
    params = {
        'component_access_token': access_token
    }
    data = {
        'component_appid': wx['app_id']
    }
    resp_json = requests.post(wx_url, params=params, data=json.dumps(data, ensure_ascii=False), verify=VERIFY).json()
    return resp_json.get('pre_auth_code')


def get_authorization_info(wx, auth_code):
    """
    获取微信授权方公众号/小程序的授权信息
    :param wx: [dict]
    :param auth_code:
    :return:
    """
    access_token = get_component_access_token(wx)
    if not access_token:
        return

    wx_url = 'https://api.weixin.qq.com/cgi-bin/component/api_query_auth'
    params = {
        'component_access_token': access_token
    }
    data = {
        'component_appid': wx['app_id'],
        'authorization_code': auth_code
    }
    resp_json = requests.post(wx_url, params=params, data=json.dumps(data, ensure_ascii=False), verify=VERIFY).json()
    return resp_json.get('authorization_info')
