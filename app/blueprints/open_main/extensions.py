# -*- coding: utf-8 -*-

import urllib
import time

from flask import current_app, request, url_for, redirect, make_response, jsonify
import requests

from . import bp_open_main
from ...models import WXAuthorizer, WXUser
from ...services.weixin import WXMsgCrypto
from ...constants import AUTHORIZERS_FOR_RELEASE_TESTING
from utils.qiniu_util import get_upload_token
from utils.redis_util import redis_client
from utils.weixin_util import get_pre_auth_code, get_authorization_info


@bp_open_main.route('/extensions/qn/upload_token/', methods=['GET'])
def get_qn_upload_token():
    """
    获取七牛上传凭证
    :return:
    """
    data = {
        'uptoken': get_upload_token(current_app.config['QINIU'])
    }
    return jsonify(data)


@bp_open_main.route('/extensions/wx/component/api/', methods=['GET', 'POST'])
def wx_component_api():
    """
    （由微信访问）微信第三方平台授权事件接收URL
    :return:
    """
    encrypt_type, msg_signature, timestamp, nonce = map(
        request.args.get,
        ('encrypt_type', 'msg_signature', 'timestamp', 'nonce')
    )
    if not all((encrypt_type, msg_signature, timestamp, nonce)):
        current_app.logger.error(u'微信第三方平台授权事件接收URL参数不完整')
        return make_response('success')

    if not encrypt_type == 'aes':
        current_app.logger.error(u'微信第三方平台授权事件接收URL加密类型错误：%s' % encrypt_type)
        return make_response('success')

    if request.method == 'GET':
        current_app.logger.info(u'微信第三方平台授权事件接收URL验证成功')
        return make_response(request.args.get('echostr', ''))

    if request.method == 'POST':
        try:
            wx = current_app.config['WEIXIN']
            crypto = WXMsgCrypto(wx)
            message = crypto.decrypt(request.data, msg_signature, timestamp, nonce)
            current_app.logger.info(message)
            assert message['AppId'] == wx['app_id'], u'微信AppId验证失败'

            if message['InfoType'] == 'component_verify_ticket':
                redis_client.set('wx:%s:component_verify_ticket' % wx['app_id'], message['ComponentVerifyTicket'])
            elif message['InfoType'] == 'unauthorized':
                wx_authorizer = WXAuthorizer.query_by_appid(message['AuthorizerAppid'])
                assert wx_authorizer, u'微信授权方查询失败'
                wx_authorizer.unauthorized()

            # 全网发布专用测试公众号/小程序
            elif message['InfoType'] == 'authorized' and message['AuthorizerAppid'] in AUTHORIZERS_FOR_RELEASE_TESTING:
                url = url_for('.wx_authorizer_login', _external=True)
                params = {
                    'auth_code': message['AuthorizationCode'],
                    'expires_in': 3600
                }
                requests.get(url, params=params)
        except Exception, e:
            current_app.logger.error(e)
        finally:
            return make_response('success')


@bp_open_main.route('/extensions/wx/authorizer/authorize/', methods=['GET'])
def wx_authorizer_authorize():
    """
    微信公众号/小程序授权：跳转到授权页面
    :return:
    """
    wx = current_app.config['WEIXIN']
    pre_auth_code = get_pre_auth_code(wx)
    if not pre_auth_code:
        current_app.logger.error(u'微信公众号/小程序授权：pre_auth_code获取失败')
        return redirect(wx['auth_error_page'])

    redirect_uri = urllib.quote_plus(url_for('.wx_authorizer_login', _external=True))
    wx_url = 'https://mp.weixin.qq.com/cgi-bin/componentloginpage?component_appid=%s&pre_auth_code=%s&redirect_uri=%s' \
             % (wx['app_id'], pre_auth_code, redirect_uri)
    return redirect(wx_url)


@bp_open_main.route('/extensions/wx/authorizer/login/', methods=['GET'])
def wx_authorizer_login():
    """
    （由微信跳转）微信公众号/小程序授权：获取微信公众号/小程序的授权信息和基本信息
    :return:
    """
    auth_code, expires_in = map(request.args.get, ('auth_code', 'expires_in'))
    wx = current_app.config['WEIXIN']
    resp = redirect(wx['auth_error_page'])
    try:
        assert auth_code and expires_in, u'微信公众号/小程序授权：auth_code获取失败'
        authorization_info = get_authorization_info(wx, auth_code)
        assert authorization_info, u'微信公众号/小程序授权：授权信息获取失败'
        appid, refresh_token, func_info, access_token, expires_in = map(
            authorization_info.get,
            ('authorizer_appid', 'authorizer_refresh_token', 'func_info', 'authorizer_access_token', 'expires_in')
        )
        assert all((appid, refresh_token, func_info, access_token, expires_in)), u'微信公众号/小程序授权：授权信息不完整'
        wx_authorizer = WXAuthorizer.query_by_appid(appid)
        if wx_authorizer:
            wx_authorizer.update_refresh_token(refresh_token)
            wx_authorizer.update_func_info(func_info)
        else:
            wx_authorizer = WXAuthorizer.create_wx_authorizer(appid, refresh_token, func_info)
        assert wx_authorizer.update_authorizer_info(), u'微信公众号/小程序授权：基本信息获取失败'
        key = 'wx_authorizer:%s:access_token' % appid
        redis_client.set(key, access_token, ex=int(expires_in) - 600)  # 提前10分钟更新access_token
        resp = redirect(wx['auth_success_page'])
    except Exception, e:
        current_app.logger.error(e)
    finally:
        return resp


@bp_open_main.route('/extensions/wx/authorizer/<appid>/api/', methods=['GET', 'POST'])
def wx_authorizer_api(appid):
    """
    （由微信访问）微信公众号/小程序消息与事件接收URL
    :param appid:
    :return:
    """
    encrypt_type, msg_signature, timestamp, nonce = map(
        request.args.get,
        ('encrypt_type', 'msg_signature', 'timestamp', 'nonce')
    )
    resp = 'success'
    if not all((encrypt_type, msg_signature, timestamp, nonce)):
        current_app.logger.error(u'微信公众号/小程序消息与事件接收URL参数不完整')
        return make_response(resp)

    if not encrypt_type == 'aes':
        current_app.logger.error(u'微信公众号/小程序消息与事件接收URL加密类型错误：%s' % encrypt_type)
        return make_response(resp)

    if request.method == 'GET':
        current_app.logger.info(u'微信公众号/小程序消息与事件接收URL验证成功')
        return make_response(request.args.get('echostr', ''))

    if request.method == 'POST':
        try:
            wx_authorizer = WXAuthorizer.query_by_appid(appid)
            assert wx_authorizer, u'微信授权方查询失败'
            wx = current_app.config['WEIXIN']
            crypto = WXMsgCrypto(wx)
            message = crypto.decrypt(request.data, msg_signature, timestamp, nonce)
            current_app.logger.info(message)
            openid, msg_type, event = map(message.get, ('FromUserName', 'MsgType', 'Event'))

            # 全网发布专用测试公众号/小程序
            if appid in AUTHORIZERS_FOR_RELEASE_TESTING:
                if msg_type == 'event':
                    template = 'weixin/reply_text_msg.xml'
                    params = {
                        'to_user': openid,
                        'from_user': message['ToUserName'],
                        'time': int(time.time()),
                        'content': event + 'from_callback'
                    }
                    msg = current_app.jinja_env.get_template(template).render(**params)
                    resp = crypto.encrypt(msg.encode('utf-8'))
                elif msg_type == 'text':
                    content = message['Content']
                    if content == 'TESTCOMPONENT_MSG_TYPE_TEXT':
                        template = 'weixin/reply_text_msg.xml'
                        params = {
                            'to_user': openid,
                            'from_user': message['ToUserName'],
                            'time': int(time.time()),
                            'content': 'TESTCOMPONENT_MSG_TYPE_TEXT_callback'
                        }
                        msg = current_app.jinja_env.get_template(template).render(**params)
                        resp = crypto.encrypt(msg.encode('utf-8'))
                    elif content.startswith('QUERY_AUTH_CODE:'):
                        from ...tasks import for_release_testing
                        for_release_testing.delay(wx_authorizer, openid, content.split(':', 1)[-1])  # celery task
                return

            # 模板消息及群发消息结果的事件推送
            if msg_type == 'event' and event in ['TEMPLATESENDJOBFINISH', 'MASSSENDJOBFINISH']:
                return

            # 用户取消关注的事件推送
            wx_user = WXUser.query_by_openid(wx_authorizer, openid)
            if not wx_user and msg_type == 'event' and event == 'unsubscribe':
                return

            # 获取微信用户基本信息
            key = 'wx_user:%s:%s:info' % (wx_authorizer.id, openid)
            if not wx_user or (msg_type == 'event' and event in ['subscribe', 'unsubscribe']):
                redis_client.delete(key)
            if redis_client.get(key) != 'off':
                redis_client.set(key, 'off', ex=86400)  # 每隔一天更新微信用户基本信息
                info = wx_authorizer.get_user_info(openid)
                if info:
                    if wx_user:
                        wx_user.update_wx_user(**info)
                    else:
                        wx_user = WXUser.create_wx_user(wx_authorizer, **info)
                else:
                    current_app.logger.error(u'微信用户基本信息获取失败')

            # TODO: 微信公众号/小程序API业务逻辑
        except Exception, e:
            current_app.logger.error(e)
        finally:
            return make_response(resp)
