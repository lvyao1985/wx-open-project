# -*- coding: utf-8 -*-

import time
import hashlib

from flask import current_app, request

from . import bp_sample_h5_api
from ...models import WXAuthorizer
from ...api_utils import *
from utils.key_util import generate_random_key


@bp_sample_h5_api.route('/wx/js_sdk_config/', methods=['GET'])
def get_wx_js_sdk_config():
    """
    获取微信JS-SDK权限验证配置
    :return:
    """
    url = request.args.get('url')
    claim_args(1201, url)
    appid = current_app.config['INTERVAL_APPID']
    wx_authorizer = WXAuthorizer.query_by_appid(appid)
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
