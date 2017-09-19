# -*- coding: utf-8 -*-

import urllib
import time

from flask import current_app, request, url_for, redirect, make_response, jsonify

from . import bp_open_main
from ...models import WXAuthorizer, WXUser
from ...services.weixin import WXMsgCrypto
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
        return redirect(wx['auth_error_page'])

    redirect_uri = urllib.quote_plus(url_for('.wx_authorizer_callback', _external=True))
    wx_url = 'https://mp.weixin.qq.com/cgi-bin/componentloginpage?component_appid=%s&pre_auth_code=%s&redirect_uri=%s' \
             % (wx['app_id'], pre_auth_code, redirect_uri)
    return redirect(wx_url)


@bp_open_main.route('/extensions/wx/authorizer/callback/', methods=['GET'])
def wx_authorizer_callback():
    """
    （由微信跳转）微信公众号/小程序授权：获取微信公众号/小程序的授权信息和基本信息并跳转
    :return:
    """
    auth_code, expires_in = map(request.args.get, ('auth_code', 'expires_in'))
    wx = current_app.config['WEIXIN']
    if not (auth_code and expires_in):
        return redirect(wx['auth_error_page'])

    authorization_info = get_authorization_info(wx, auth_code)
    if not authorization_info:
        return redirect(wx['auth_error_page'])

    appid, refresh_token, func_info, access_token, expires_in = map(
        authorization_info.get,
        ('authorizer_appid', 'authorizer_refresh_token', 'func_info', 'authorizer_access_token', 'expires_in')
    )
    if not all((appid, refresh_token, func_info, access_token, expires_in)):
        return redirect(wx['auth_error_page'])

    wx_authorizer = WXAuthorizer.query_by_appid(appid)
    if wx_authorizer:
        wx_authorizer.update_refresh_token(refresh_token)
        wx_authorizer.update_func_info(func_info)
    else:
        wx_authorizer = WXAuthorizer.create_wx_authorizer(appid, refresh_token, func_info)
    if not wx_authorizer.update_authorizer_info():
        return redirect(wx['auth_error_page'])

    key = 'wx_authorizer:%s:access_token' % appid
    redis_client.set(key, access_token, ex=int(expires_in) - 600)  # 提前10分钟更新access_token
    return redirect(wx['auth_success_page'])


@bp_open_main.route('/extensions/wx/authorizer/<appid>/api/', methods=['GET', 'POST'])
def wx_authorizer_api(appid):
    """
    （由微信访问）微信授权方公众号消息与事件接收URL
    :param appid:
    :return:
    """
    encrypt_type, msg_signature, timestamp, nonce = map(
        request.args.get,
        ('encrypt_type', 'msg_signature', 'timestamp', 'nonce')
    )
    if not all((encrypt_type, msg_signature, timestamp, nonce)):
        current_app.logger.error(u'微信公众号消息与事件接收URL参数不完整')
        return make_response('success')

    if not encrypt_type == 'aes':
        current_app.logger.error(u'微信公众号消息与事件接收URL加密类型错误：%s' % encrypt_type)
        return make_response('success')

    if request.method == 'GET':
        current_app.logger.info(u'微信公众号消息与事件接收URL验证成功')
        return make_response(request.args.get('echostr', ''))

    if request.method == 'POST':
        resp = 'success'
        try:
            wx_authorizer = WXAuthorizer.query_by_appid(appid)
            assert wx_authorizer, u'微信授权方查询失败'
            wx = current_app.config['WEIXIN']
            crypto = WXMsgCrypto(wx)
            message = crypto.decrypt(request.data, msg_signature, timestamp, nonce)
            current_app.logger.info(message)
            msg_type = message['MsgType']

            # 全网发布专用测试公众号
            if appid == 'wx570bc396a51b8ff8':
                if msg_type == 'event':
                    template = 'weixin/reply_text_msg.xml'
                    params = {
                        'to_user': message['FromUserName'],
                        'from_user': message['ToUserName'],
                        'time': int(time.time()),
                        'content': message['Event'] + 'from_callback'
                    }
                    msg = current_app.jinja_env.get_template(template).render(**params)
                    resp = crypto.encrypt(msg.encode('utf-8'))
                elif msg_type == 'text':
                    msg_content = message['Content']
                    if msg_content == 'TESTCOMPONENT_MSG_TYPE_TEXT':
                        template = 'weixin/reply_text_msg.xml'
                        params = {
                            'to_user': message['FromUserName'],
                            'from_user': message['ToUserName'],
                            'time': int(time.time()),
                            'content': 'TESTCOMPONENT_MSG_TYPE_TEXT_callback'
                        }
                        msg = current_app.jinja_env.get_template(template).render(**params)
                        resp = crypto.encrypt(msg.encode('utf-8'))
                    elif msg_content.startswith('QUERY_AUTH_CODE:'):
                        from ...tasks import for_release_testing
                        for_release_testing.apply_async(
                            (wx_authorizer, message['FromUserName'], msg_content.split(':', 1)[-1]),
                            countdown=1
                        )  # celery task
                        resp = ''
                return

            # 模板消息及群发消息结果的事件推送
            if msg_type == 'event' and message['Event'] in ['TEMPLATESENDJOBFINISH', 'MASSSENDJOBFINISH']:
                return

            # 获取微信用户基本信息
            openid = message['FromUserName']
            wx_user = WXUser.query_by_openid(wx_authorizer, openid)
            key = 'wx_user:%s:%s:info' % (wx_authorizer.id, openid)
            if not wx_user or (msg_type == 'event' and message['Event'] in ['subscribe', 'unsubscribe']):
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

            # TODO: 微信授权方公众号API业务逻辑
        except Exception, e:
            current_app.logger.error(e)
        finally:
            return make_response(resp)
