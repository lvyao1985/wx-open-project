# -*- coding: utf-8 -*-

from uuid import uuid1
import datetime
import json

from flask import current_app
from peewee import *
from playhouse.shortcuts import model_to_dict
from werkzeug.security import generate_password_hash, check_password_hash
import requests

from . import db
from .constants import DEFAULT_PER_PAGE
from utils.redis_util import redis_client
from utils.weixin_util import VERIFY, get_component_access_token


_to_set = (lambda r: set(r) if r else set())
_nullable_strip = (lambda s: s.strip() or None if s else None)


class BaseModel(Model):
    """
    所有model的基类
    """
    id = PrimaryKeyField()  # 主键
    uuid = UUIDField(unique=True, default=uuid1)  # UUID
    create_time = DateTimeField(default=datetime.datetime.now)  # 创建时间
    update_time = DateTimeField(default=datetime.datetime.now)  # 更新时间
    weight = IntegerField(default=0)  # 排序权重

    class Meta:
        database = db
        only_save_dirty = True

    @classmethod
    def _exclude_fields(cls):
        """
        转换为dict表示时排除在外的字段
        :return:
        """
        return {'create_time', 'update_time'}

    @classmethod
    def _extra_attributes(cls):
        """
        转换为dict表示时额外增加的属性
        :return:
        """
        return {'iso_create_time', 'iso_update_time'}

    @classmethod
    def query_by_id(cls, _id):
        """
        根据id查询
        :param _id:
        :return:
        """
        obj = None
        try:
            obj = cls.get(cls.id == _id)
        finally:
            return obj

    @classmethod
    def query_by_uuid(cls, _uuid):
        """
        根据uuid查询
        :param _uuid:
        :return:
        """
        obj = None
        try:
            obj = cls.get(cls.uuid == _uuid)
        finally:
            return obj

    @classmethod
    def count(cls, select_query=None):
        """
        根据查询条件计数
        :param select_query: [SelectQuery or None]
        :return:
        """
        cnt = 0
        try:
            if select_query is None:
                select_query = cls.select()
            cnt = select_query.count()
        finally:
            return cnt

    @classmethod
    def iterator(cls, select_query=None, order_by=None, page=None, per_page=None):
        """
        根据查询条件返回迭代器
        :param select_query: [SelectQuery or None]
        :param order_by: [iterable or None]
        :param page:
        :param per_page:
        :return:
        """
        try:
            if select_query is None:
                select_query = cls.select()

            if order_by:
                _fields = cls._meta.fields
                clauses = []
                for item in order_by:
                    desc, attr = item.startswith('-'), item.lstrip('+-')
                    if attr in cls._exclude_fields():
                        continue
                    if attr in cls._extra_attributes():
                        attr = attr.split('_', 1)[-1]
                    if attr in _fields:
                        clauses.append(_fields[attr].desc() if desc else _fields[attr])
                if clauses:
                    select_query = select_query.order_by(*clauses)

            if page or per_page:
                select_query = select_query.paginate(int(page or 1), int(per_page or DEFAULT_PER_PAGE))

            return select_query.naive().iterator()

        except Exception, e:
            current_app.logger.error(e)
            return iter([])

    def to_dict(self, only=None, exclude=None, recurse=False, backrefs=False, max_depth=None):
        """
        转换为dict表示
        :param only: [iterable or None]
        :param exclude: [iterable or None]
        :param recurse: [bool]
        :param backrefs: [bool]
        :param max_depth:
        :return:
        """
        try:
            only = _to_set(only)
            exclude = _to_set(exclude) | self._exclude_fields()

            _fields = self._meta.fields
            only_fields = {_fields[k] for k in only if k in _fields}
            exclude_fields = {_fields[k] for k in exclude if k in _fields}
            extra_attrs = self._extra_attributes() - exclude
            if only:
                extra_attrs &= only
                if not only_fields:
                    exclude_fields = _fields.values()

            return model_to_dict(self, recurse=recurse, backrefs=backrefs, only=only_fields, exclude=exclude_fields,
                                 extra_attrs=extra_attrs, max_depth=max_depth)

        except Exception, e:
            current_app.logger.error(e)
            return {}

    def modified_fields(self, exclude=None):
        """
        与数据库中对应的数据相比，数值有变动的字段名称列表
        :param exclude: [iterable or None]
        :return:
        """
        try:
            exclude = _to_set(exclude)
            db_obj = self.query_by_id(self.id)
            return filter(lambda f: getattr(self, f) != getattr(db_obj, f) and f not in exclude,
                          self._meta.sorted_field_names)

        except Exception, e:
            current_app.logger.error(e)

    def change_weight(self, weight):
        """
        修改排序权重
        :param weight:
        :return:
        """
        try:
            self.weight = weight
            self.save()
            return self

        except Exception, e:
            current_app.logger.error(e)

    def iso_create_time(self):
        return self.create_time.isoformat()

    def iso_update_time(self):
        return self.update_time.isoformat()


class Admin(BaseModel):
    """
    管理员
    """
    name = CharField(max_length=32, unique=True)  # 用户名
    password = CharField()  # 密码
    mobile = CharField(null=True)  # 手机号码
    last_login_time = DateTimeField(null=True)  # 最近登录时间
    last_login_ip = CharField(null=True)  # 最近登录IP
    authority = BigIntegerField(default=0)  # 权限

    class Meta:
        db_table = 'admin'

    @classmethod
    def _exclude_fields(cls):
        return BaseModel._exclude_fields() | {'password', 'last_login_time'}

    @classmethod
    def _extra_attributes(cls):
        return BaseModel._extra_attributes() | {'iso_last_login_time'}

    @classmethod
    def query_by_name(cls, name):
        """
        根据用户名查询
        :param name:
        :return:
        """
        admin = None
        try:
            admin = cls.get(cls.name == name)
        finally:
            return admin

    @classmethod
    def create_admin(cls, name, password, mobile=None, authority=0):
        """
        创建管理员
        :param name:
        :param password:
        :param mobile:
        :param authority:
        :return:
        """
        try:
            return cls.create(
                name=name.strip(),
                password=generate_password_hash(password),
                mobile=_nullable_strip(mobile),
                authority=authority
            )

        except Exception, e:
            current_app.logger.error(e)

    def check_password(self, password):
        """
        核对密码
        :param password:
        :return:
        """
        return check_password_hash(self.password, password)

    def change_password(self, password):
        """
        修改密码
        :param password:
        :return:
        """
        try:
            self.password = generate_password_hash(password)
            self.update_time = datetime.datetime.now()
            self.save()
            return self

        except Exception, e:
            current_app.logger.error(e)

    def login(self, ip):
        """
        登录
        :param ip:
        :return:
        """
        try:
            self.last_login_time = datetime.datetime.now()
            self.last_login_ip = ip
            self.save()
            return self

        except Exception, e:
            current_app.logger.error(e)

    def iso_last_login_time(self):
        return self.last_login_time.isoformat() if self.last_login_time else None


class WXAuthorizer(BaseModel):
    """
    微信授权方公众号/小程序
    """
    authorized = BooleanField(default=True)  # 是否已授权
    appid = CharField(max_length=40, unique=True)
    refresh_token = CharField()
    func_info = TextField()

    authorizer_info = TextField(null=True)
    service_type = IntegerField(null=True)
    verify_type = IntegerField(null=True)
    nick_name = CharField(null=True)
    signature = CharField(null=True)
    head_img = CharField(null=True)
    qrcode_url = CharField(null=True)
    principal_name = CharField(null=True)
    user_name = CharField(null=True)
    alias = CharField(null=True)
    business_info = TextField(null=True)
    mini_program_info = TextField(null=True)

    class Meta:
        db_table = 'wx_authorizer'

    @classmethod
    def _exclude_fields(cls):
        return BaseModel._exclude_fields() | {'refresh_token', 'func_info', 'authorizer_info', 'business_info',
                                              'mini_program_info'}

    @classmethod
    def _extra_attributes(cls):
        return BaseModel._extra_attributes() | {'array_func_info', 'dict_authorizer_info', 'dict_business_info',
                                                'dict_mini_program_info'}

    @classmethod
    def query_by_appid(cls, appid):
        """
        根据appid查询
        :param appid:
        :return:
        """
        authorizer = None
        try:
            authorizer = cls.get(cls.appid == appid)
        finally:
            return authorizer

    @classmethod
    def create_wx_authorizer(cls, appid, refresh_token, func_info):
        """
        创建微信授权方公众号/小程序
        :param appid:
        :param refresh_token:
        :param func_info: [list]
        :return:
        """
        try:
            return cls.create(
                appid=appid.strip(),
                refresh_token=refresh_token.strip(),
                func_info=repr(func_info)
            )

        except Exception, e:
            current_app.logger.error(e)

    def unauthorized(self):
        """
        取消授权
        :return:
        """
        try:
            if self.authorized:
                self.authorized = False
                self.update_time = datetime.datetime.now()
                self.save()
            return self

        except Exception, e:
            current_app.logger.error(e)

    def update_refresh_token(self, refresh_token):
        """
        更新refresh_token
        :param refresh_token:
        :return:
        """
        try:
            if self.refresh_token != refresh_token:
                self.refresh_token = refresh_token
                self.update_time = datetime.datetime.now()
                self.save()
            return self

        except Exception, e:
            current_app.logger.error(e)

    def update_func_info(self, func_info):
        """
        更新func_info
        :param func_info: [list]
        :return:
        """
        try:
            if self.func_info != repr(func_info):
                self.func_info = repr(func_info)
                self.update_time = datetime.datetime.now()
                self.save()
            return self

        except Exception, e:
            current_app.logger.error(e)

    def update_authorizer_info(self):
        """
        更新authorizer_info
        :return:
        """
        try:
            wx = current_app.config['WEIXIN']
            component_access_token = get_component_access_token(wx)
            if not component_access_token:
                return

            wx_url = 'https://api.weixin.qq.com/cgi-bin/component/api_get_authorizer_info'
            params = {
                'component_access_token': component_access_token
            }
            data = {
                'component_appid': wx['app_id'],
                'authorizer_appid': self.appid
            }
            resp_json = requests.post(wx_url, params=params, data=json.dumps(data, ensure_ascii=False), verify=VERIFY).json()
            authorizer_info, authorization_info = map(resp_json.get, ('authorizer_info', 'authorization_info'))
            if not (authorizer_info and authorization_info):
                return

            (service_type_info, verify_type_info, nick_name, signature, head_img, qrcode_url, principal_name, user_name,
             alias, business_info, mini_program_info) = map(
                authorizer_info.get,
                ('service_type_info', 'verify_type_info', 'nick_name', 'signature', 'head_img', 'qrcode_url',
                 'principal_name', 'user_name', 'alias', 'business_info', 'miniprograminfo')
            )
            self.authorized = True
            self.func_info = repr(authorization_info.get('func_info'))
            self.authorizer_info = repr(authorizer_info)
            self.service_type = service_type_info.get('id') if service_type_info else None
            self.verify_type = verify_type_info.get('id') if verify_type_info else None
            self.nick_name = _nullable_strip(nick_name)
            self.signature = _nullable_strip(signature)
            self.head_img = _nullable_strip(head_img)
            self.qrcode_url = _nullable_strip(qrcode_url)
            self.principal_name = _nullable_strip(principal_name)
            self.user_name = _nullable_strip(user_name)
            self.alias = _nullable_strip(alias)
            self.business_info = repr(business_info) if business_info else None
            self.mini_program_info = repr(mini_program_info) if mini_program_info else None
            if self.modified_fields():
                self.update_time = datetime.datetime.now()
                self.save()
            return self

        except Exception, e:
            current_app.logger.error(e)

    def get_access_token(self):
        """
        获取access_token
        :return:
        """
        key = 'wx_authorizer:%s:access_token' % self.appid
        access_token = redis_client.get(key)
        if access_token:
            return access_token

        wx = current_app.config['WEIXIN']
        component_access_token = get_component_access_token(wx)
        if not component_access_token:
            return

        wx_url = 'https://api.weixin.qq.com/cgi-bin/component/api_authorizer_token'
        params = {
            'component_access_token': component_access_token
        }
        data = {
            'component_appid': wx['app_id'],
            'authorizer_appid': self.appid,
            'authorizer_refresh_token': self.refresh_token
        }
        resp_json = requests.post(wx_url, params=params, data=json.dumps(data, ensure_ascii=False), verify=VERIFY).json()
        access_token, expires_in, refresh_token = map(
            resp_json.get,
            ('authorizer_access_token', 'expires_in', 'authorizer_refresh_token')
        )
        if not all((access_token, expires_in, refresh_token)):
            return

        self.update_refresh_token(refresh_token)
        redis_client.set(key, access_token, ex=int(expires_in) - 600)  # 提前10分钟更新access_token
        return access_token

    def get_jsapi_ticket(self):
        """
        获取jsapi_ticket
        :return:
        """
        key = 'wx_authorizer:%s:jsapi_ticket' % self.appid
        jsapi_ticket = redis_client.get(key)
        if jsapi_ticket:
            return jsapi_ticket

        access_token = self.get_access_token()
        if not access_token:
            return

        wx_url = 'https://api.weixin.qq.com/cgi-bin/ticket/getticket'
        params = {
            'access_token': access_token,
            'type': 'jsapi'
        }
        resp_json = requests.get(wx_url, params=params, verify=VERIFY).json()
        jsapi_ticket, expires_in = map(resp_json.get, ('ticket', 'expires_in'))
        if not (jsapi_ticket and expires_in):
            return

        redis_client.set(key, jsapi_ticket, ex=int(expires_in) - 600)  # 提前10分钟更新jsapi_ticket
        return jsapi_ticket

    def get_user_info(self, openid):
        """
        获取微信用户基本信息
        :param openid:
        :return:
        """
        access_token = self.get_access_token()
        if not access_token:
            return

        wx_url = 'https://api.weixin.qq.com/cgi-bin/user/info'
        params = {
            'access_token': access_token,
            'openid': openid,
            'lang': 'zh_CN'
        }
        resp = requests.get(wx_url, params=params, verify=VERIFY)
        resp.encoding = 'utf-8'
        info = resp.json()
        if not info.get('errcode'):
            return info

    def get_user_info_with_authorization(self, code):
        """
        获取微信用户基本信息（网页授权）
        :param code:
        :return:
        """
        wx = current_app.config['WEIXIN']
        component_access_token = get_component_access_token(wx)
        if not component_access_token:
            return

        # 通过code换取网页授权access_token
        wx_url = 'https://api.weixin.qq.com/sns/oauth2/component/access_token'
        params = {
            'appid': self.appid,
            'code': code,
            'grant_type': 'authorization_code',
            'component_appid': wx['app_id'],
            'component_access_token': component_access_token
        }
        resp_json = requests.get(wx_url, params=params, verify=VERIFY).json()
        access_token, openid, refresh_token = map(resp_json.get, ('access_token', 'openid', 'refresh_token'))
        if not (access_token and openid):
            return

        # 拉取用户信息
        wx_url = 'https://api.weixin.qq.com/sns/userinfo'
        params = {
            'access_token': access_token,
            'openid': openid,
            'lang': 'zh_CN'
        }
        resp = requests.get(wx_url, params=params, verify=VERIFY)
        resp.encoding = 'utf-8'
        info = resp.json()
        if not info.get('errcode'):
            return info

    def get_temp_image_media(self, media_id):
        """
        获取临时图片素材
        :param media_id:
        :return:
        """
        access_token = self.get_access_token()
        if not access_token:
            return

        wx_url = 'https://api.weixin.qq.com/cgi-bin/media/get'
        params = {
            'access_token': access_token,
            'media_id': media_id
        }
        resp = requests.get(wx_url, params=params, verify=VERIFY)
        content_type = resp.headers.get('Content-Type')
        if content_type and content_type.startswith('image/'):
            return resp.content

    def upload_temp_media(self, media_type, file_name, file_data, content_type):
        """
        上传临时素材
        :param media_type: 'image' - 图片，'voice' - 语音，'video' - 视频，'thumb' - 缩略图
        :param file_name:
        :param file_data:
        :param content_type:
        :return:
        """
        access_token = self.get_access_token()
        if not access_token:
            return

        wx_url = 'https://api.weixin.qq.com/cgi-bin/media/upload'
        params = {
            'access_token': access_token,
            'type': media_type
        }
        files = {
            'media': (file_name, file_data, content_type)
        }
        return requests.post(wx_url, params=params, files=files, verify=VERIFY).json().get('media_id')

    def send_custom_message(self, openid, msg_type, msg_data):
        """
        发送客服消息
        :param openid:
        :param msg_type:
        :param msg_data: [dict]
        :return:
        """
        access_token = self.get_access_token()
        if not access_token:
            return

        wx_url = 'https://api.weixin.qq.com/cgi-bin/message/custom/send'
        params = {
            'access_token': access_token
        }
        data = {
            'touser': str(openid),
            'msgtype': str(msg_type),
            str(msg_type): msg_data
        }
        return requests.post(wx_url, params=params, data=json.dumps(data, ensure_ascii=False), verify=VERIFY).json()

    def send_template_message(self, openid, template_id, msg_data, url=None, miniprogram=None):
        """
        发送模板消息
        :param openid:
        :param template_id:
        :param msg_data: [dict]
        :param url:
        :param miniprogram: [dict or None]
        :return:
        """
        access_token = self.get_access_token()
        if not access_token:
            return

        wx_url = 'https://api.weixin.qq.com/cgi-bin/message/template/send'
        params = {
            'access_token': access_token
        }
        data = {
            'touser': str(openid),
            'template_id': str(template_id),
            'data': msg_data
        }
        if url:
            data['url'] = str(url)
        if miniprogram:
            data['miniprogram'] = miniprogram
        return requests.post(wx_url, params=params, data=json.dumps(data, ensure_ascii=False), verify=VERIFY).json()

    def create_menu(self, buttons):
        """
        创建自定义菜单
        :param buttons: [list]
        :return:
        """
        access_token = self.get_access_token()
        if not access_token:
            return

        wx_url = 'https://api.weixin.qq.com/cgi-bin/menu/create'
        params = {
            'access_token': access_token
        }
        data = {
            'button': buttons
        }
        return requests.post(wx_url, params=params, data=json.dumps(data, ensure_ascii=False), verify=VERIFY).json()

    def generate_qrcode_with_scene(self, action, scene, expires=30):
        """
        生成带参数的二维码
        :param action: 'QR_SCENE' - 临时整型参数值，'QR_STR_SCENE' - 临时字符串参数值，
                       'QR_LIMIT_SCENE' - 永久整型参数值，'QR_LIMIT_STR_SCENE' - 永久字符串参数值
        :param scene:
        :param expires:
        :return:
        """
        access_token = self.get_access_token()
        if not access_token:
            return

        wx_url = 'https://api.weixin.qq.com/cgi-bin/qrcode/create'
        params = {
            'access_token': access_token
        }
        data = {
            'action_name': str(action),
            'action_info': {
                'scene': {'scene_str': str(scene)} if action.endswith('_STR_SCENE') else {'scene_id': int(scene)}
            }
        }
        if not action.startswith('QR_LIMIT_'):
            data['expire_seconds'] = int(expires)
        resp_json = requests.post(wx_url, params=params, data=json.dumps(data, ensure_ascii=False), verify=VERIFY).json()
        url, ticket = map(resp_json.get, ('url', 'ticket'))
        if not (url and ticket):
            return

        wx_url = 'https://mp.weixin.qq.com/cgi-bin/showqrcode'
        params = {
            'ticket': ticket
        }
        resp = requests.get(wx_url, params=params, verify=VERIFY)
        content_type = resp.headers.get('Content-Type')
        if content_type and content_type.startswith('image/'):
            return url, resp.url, resp.content

    def array_func_info(self):
        return [item['funcscope_category']['id'] for item in eval(self.func_info)]

    def dict_authorizer_info(self):
        return eval(self.authorizer_info) if self.authorizer_info else {}

    def dict_business_info(self):
        return eval(self.business_info) if self.business_info else {}

    def dict_mini_program_info(self):
        return eval(self.mini_program_info) if self.mini_program_info else {}


class WXUser(BaseModel):
    """
    微信用户
    """
    wx_authorizer = ForeignKeyField(WXAuthorizer, on_delete='CASCADE')
    openid = CharField(max_length=40, index=True)
    unionid = CharField(null=True)
    nickname = CharField(null=True)
    sex = IntegerField(null=True)
    country = CharField(null=True)
    province = CharField(null=True)
    city = CharField(null=True)
    headimgurl = CharField(null=True)

    subscribe = IntegerField(null=True)
    subscribe_time = IntegerField(null=True)
    language = CharField(null=True)
    remark = CharField(null=True)
    tagid_list = TextField(null=True)

    class Meta:
        db_table = 'wx_user'

    @classmethod
    def _exclude_fields(cls):
        return BaseModel._exclude_fields() | {'subscribe_time', 'tagid_list'}

    @classmethod
    def _extra_attributes(cls):
        return BaseModel._extra_attributes() | {'iso_subscribe_time', 'array_tagid_list'}

    @classmethod
    def query_by_openid(cls, wx_authorizer, openid):
        """
        根据openid查询
        :param wx_authorizer:
        :param openid:
        :return:
        """
        wx_user = None
        try:
            wx_user = cls.get(cls.wx_authorizer == wx_authorizer, cls.openid == openid)
        finally:
            return wx_user

    @classmethod
    def create_wx_user(cls, wx_authorizer, openid, unionid=None, nickname=None, sex=None, country=None, province=None,
                       city=None, headimgurl=None, subscribe=None, subscribe_time=None, language=None, remark=None,
                       tagid_list=None, **kwargs):
        """
        创建微信用户
        :param wx_authorizer:
        :param openid:
        :param unionid:
        :param nickname:
        :param sex:
        :param country:
        :param province:
        :param city:
        :param headimgurl:
        :param subscribe:
        :param subscribe_time:
        :param language:
        :param remark:
        :param tagid_list: [list or None]
        :param kwargs:
        :return:
        """
        try:
            return cls.create(
                wx_authorizer=wx_authorizer,
                openid=openid.strip(),
                unionid=_nullable_strip(unionid),
                nickname=_nullable_strip(nickname),
                sex=sex,
                country=_nullable_strip(country),
                province=_nullable_strip(province),
                city=_nullable_strip(city),
                headimgurl=_nullable_strip(headimgurl),
                subscribe=subscribe,
                subscribe_time=subscribe_time,
                language=_nullable_strip(language),
                remark=_nullable_strip(remark),
                tagid_list=','.join(map(str, tagid_list)) if tagid_list else None
            )

        except Exception, e:
            current_app.logger.error(e)

    def update_wx_user(self, subscribe, unionid=None, nickname=None, sex=None, country=None, province=None, city=None,
                       headimgurl=None, subscribe_time=None, language=None, remark=None, tagid_list=None, **kwargs):
        """
        更新微信用户
        :param subscribe:
        :param unionid:
        :param nickname:
        :param sex:
        :param country:
        :param province:
        :param city:
        :param headimgurl:
        :param subscribe_time:
        :param language:
        :param remark:
        :param tagid_list: [list or None]
        :param kwargs:
        :return:
        """
        try:
            self.subscribe = subscribe
            if subscribe:
                self.unionid = _nullable_strip(unionid)
                self.nickname = _nullable_strip(nickname)
                self.sex = sex
                self.country = _nullable_strip(country)
                self.province = _nullable_strip(province)
                self.city = _nullable_strip(city)
                self.headimgurl = _nullable_strip(headimgurl)
                self.subscribe_time = subscribe_time
                self.language = _nullable_strip(language)
                self.remark = _nullable_strip(remark)
                self.tagid_list = ','.join(map(str, tagid_list)) if tagid_list else None
            if self.modified_fields():
                self.update_time = datetime.datetime.now()
                self.save()
            return self

        except Exception, e:
            current_app.logger.error(e)

    def iso_subscribe_time(self):
        return datetime.datetime.fromtimestamp(self.subscribe_time).isoformat() if self.subscribe_time else None

    def array_tagid_list(self):
        return map(int, self.tagid_list.split(',')) if self.tagid_list else []


models = [Admin, WXAuthorizer, WXUser]
