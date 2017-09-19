# -*- coding: utf-8 -*-

import time
import hashlib

from flask import request

from . import bp_h5_api
from ...models import WXAuthorizer
from ...api_utils import *
from utils.key_util import generate_random_key


@bp_h5_api.route('/wx/authorizer/<appid>/js_sdk_config/', methods=['GET'])
def get_wx_authorizer_js_sdk_config(appid):
    """
    获取微信授权方公众号JS-SDK权限验证配置
    :param appid:
    :return:
    """
    url = request.args.get('url')
    wx_authorizer = WXAuthorizer.query_by_appid(appid)
    claim_args_true(1104, wx_authorizer)
    claim_args(1201, url)
    jsapi_ticket = wx_authorizer.get_jsapi_ticket()
    claim_args(1810, jsapi_ticket)

    noncestr = generate_random_key(16)
    timestamp = int(time.time())
    items = ['jsapi_ticket=%s' % jsapi_ticket, 'noncestr=%s' % noncestr, 'timestamp=%s' % timestamp, 'url=%s' % url]
    items.sort()
    signature = hashlib.sha1('&'.join(items)).hexdigest()
    data = {
        'appid': appid,
        'noncestr': noncestr,
        'signature': signature,
        'timestamp': timestamp
    }
    return api_success_response(data)
