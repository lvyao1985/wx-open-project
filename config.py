# -*- coding: utf-8 -*-

from os import environ
from logging.handlers import RotatingFileHandler
import logging


class Config(object):
    """
    配置
    """
    _project_name = 'wx-open-project'  # TODO: 项目名称

    # mysql
    MYSQL = {
        'charset': 'utf8mb4',
        'host': environ.get('FLASK_MYSQL_HOST') or '127.0.0.1',
        'port': int(environ.get('FLASK_MYSQL_PORT') or 3306),
        'user': environ.get('FLASK_MYSQL_USER'),
        'password': environ.get('FLASK_MYSQL_PASSWORD'),
        'database': environ.get('FLASK_MYSQL_DB') or _project_name.replace('-', '_')
    }

    # celery
    BROKER_URL = 'amqp://%s:%s@%s:%s/%s' % (environ.get('CELERY_BROKER_USER'),
                                            environ.get('CELERY_BROKER_PASSWORD'),
                                            environ.get('CELERY_BROKER_HOST') or '127.0.0.1',
                                            environ.get('CELERY_BROKER_PORT') or 5672,
                                            environ.get('CELERY_BROKER_VHOST') or _project_name)
    CELERY_RESULT_BACKEND = 'redis://%s:%s/%s' % (environ.get('CELERY_BACKEND_HOST') or '127.0.0.1',
                                                  environ.get('CELERY_BACKEND_PORT') or 6379,
                                                  environ.get('CELERY_BACKEND_DB') or 0)
    CELERY_ACCEPT_CONTENT = ['pickle']
    CELERY_TASK_SERIALIZER = 'pickle'
    CELERY_RESULT_SERIALIZER = 'pickle'
    CELERY_TIMEZONE = 'Asia/Shanghai'

    # 七牛
    QINIU = {
        'access_key': environ.get('QINIU_ACCESS_KEY'),
        'secret_key': environ.get('QINIU_SECRET_KEY'),
        'bucket': environ.get('QINIU_BUCKET'),
        'domain': environ.get('QINIU_DOMAIN')
    }

    # 云片
    YUNPIAN = {
        'key': environ.get('YUNPIAN_KEY'),
        'single_send': 'https://sms.yunpian.com/v2/sms/single_send.json',
        'batch_send': 'https://sms.yunpian.com/v2/sms/batch_send.json'
    }

    # 微信（开放平台）第三方平台
    WEIXIN = {
        'app_id': environ.get('WEIXIN_APP_ID'),
        'app_secret': environ.get('WEIXIN_APP_SECRET'),
        'token': environ.get('WEIXIN_TOKEN'),
        'aes_key': environ.get('WEIXIN_AES_KEY'),
        'auth_error_page': environ.get('WEIXIN_AUTH_ERROR_PAGE') or '/',
        'auth_success_page': environ.get('WEIXIN_AUTH_SUCCESS_PAGE') or '/'
    }

    # 微信授权方公众号appid
    SAMPLE_APPID = 'wx0000000000000000'

    @staticmethod
    def init_app(app):
        """
        初始化flask应用对象
        :param app:
        :return:
        """
        file_handler = RotatingFileHandler('backend.log', maxBytes=1024 * 1024 * 100, backupCount=10, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(
            logging.Formatter(u'[%(asctime)s] - %(pathname)s (%(lineno)s) - [%(levelname)s] - %(message)s')
        )
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)


class DevelopmentConfig(Config):
    """
    开发环境配置
    """
    DEBUG = True
    SERVER_NAME = 'lvh.me:5000'
    SUBDOMAIN = {
        'cms_main': 'cms',
        'cms_api': 'cms',
        'open_main': 'open',
        'open_api': 'open',
        'h5_main': 'h5',
        'h5_api': 'h5',
        'sample_h5_main': 'sample.h5',
        'sample_h5_api': 'sample.h5'
    }


class ProductionConfig(Config):
    """
    生产环境配置
    """
    SERVER_NAME = ''  # TODO: 域名
    SUBDOMAIN = {
        'cms_main': 'cms',
        'cms_api': 'cms',
        'open_main': 'open',
        'open_api': 'open',
        'h5_main': 'h5',
        'h5_api': 'h5',
        'sample_h5_main': '%s.h5' % Config.SAMPLE_APPID,
        'sample_h5_api': '%s.h5' % Config.SAMPLE_APPID
    }


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,

    'default': DevelopmentConfig
}
