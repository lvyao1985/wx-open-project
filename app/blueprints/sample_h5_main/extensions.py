# -*- coding: utf-8 -*-

import urllib

from flask import current_app, request, url_for, redirect, make_response, jsonify, abort

from . import bp_sample_h5_main
from ...models import WXAuthorizer, WXUser
from ...constants import WX_USER_COOKIE_KEY, WX_USER_COOKIE_VALID_DAYS
from utils.aes_util import encrypt
from utils.qiniu_util import get_upload_token


@bp_sample_h5_main.route('/extensions/qn/upload_token/', methods=['GET'])
def get_qn_upload_token():
    """
    获取七牛上传凭证
    :return:
    """
    data = {
        'uptoken': get_upload_token(current_app.config['QINIU'])
    }
    return jsonify(data)


@bp_sample_h5_main.route('/extensions/wx/user/authorize/', methods=['GET'])
def wx_user_authorize():
    """
    微信公众号网页授权：跳转到微信登录页面
    :return:
    """
    appid = current_app.config['SAMPLE_APPID']
    redirect_uri = urllib.quote_plus(url_for('.wx_user_login', _external=True))
    state = request.args.get('state') or urllib.quote_plus('/')
    component_appid = current_app.config['WEIXIN']['app_id']
    wx_url = 'https://open.weixin.qq.com/connect/oauth2/authorize?appid=%s&redirect_uri=%s&response_type=code' \
             '&scope=snsapi_userinfo&state=%s&component_appid=%s#wechat_redirect' \
             % (appid, redirect_uri, state, component_appid)
    return redirect(wx_url)


@bp_sample_h5_main.route('/extensions/wx/user/login/', methods=['GET'])
def wx_user_login():
    """
    （由微信跳转）微信公众号网页授权：获取微信用户基本信息，登录并跳转
    :return:
    """
    code, state, appid = map(request.args.get, ('code', 'state', 'appid'))
    resp = make_response(redirect(urllib.unquote_plus(state) if state else '/'))
    try:
        assert code, u'微信公众号网页授权：code获取失败'
        assert appid == current_app.config['SAMPLE_APPID'], u'微信公众号网页授权：appid验证失败'
        wx_authorizer = WXAuthorizer.query_by_appid(appid)
        assert wx_authorizer, u'微信公众号网页授权：微信授权方查询失败'
        info = wx_authorizer.get_user_info_with_authorization(code)
        assert info, u'微信公众号网页授权：微信用户基本信息获取失败'
        wx_user = WXUser.query_by_openid(wx_authorizer, info['openid']) or WXUser.create_wx_user(wx_authorizer, **info)
        assert wx_user, u'微信公众号网页授权：微信用户查询或创建失败'
        resp.set_cookie(WX_USER_COOKIE_KEY, value=encrypt(wx_user.uuid.hex), max_age=86400 * WX_USER_COOKIE_VALID_DAYS)
    except Exception, e:
        current_app.logger.error(e)
    finally:
        return resp


@bp_sample_h5_main.route('/extensions/testing/wx/user/<uuid:wx_user_uuid>/login/', methods=['GET'])
def wx_user_login_for_testing(wx_user_uuid):
    """
    微信用户登录（测试）
    :param wx_user_uuid:
    :return:
    """
    state = request.args.get('state')
    wx_user = WXUser.query_by_uuid(wx_user_uuid)
    if not wx_user or wx_user.wx_authorizer.appid != current_app.config['SAMPLE_APPID']:
        abort(404)

    resp = make_response(redirect(urllib.unquote_plus(state) if state else '/'))
    resp.set_cookie(WX_USER_COOKIE_KEY, value=encrypt(wx_user.uuid.hex), max_age=86400)
    return resp


@bp_sample_h5_main.route('/extensions/testing/wx/user/logout/', methods=['GET'])
def wx_user_logout_for_testing():
    """
    微信用户退出（测试）
    :return:
    """
    state = request.args.get('state')
    resp = make_response(redirect(urllib.unquote_plus(state) if state else '/'))
    resp.set_cookie(WX_USER_COOKIE_KEY, max_age=0)
    return resp
