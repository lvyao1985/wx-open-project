# -*- coding: utf-8 -*-

from flask import Flask
from peewee import MySQLDatabase
from celery import Celery

from config import config


db = MySQLDatabase(None)


def create_app(config_name):
    """
    创建flask应用对象
    :param config_name:
    :return:
    """
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    db.init(**app.config['MYSQL'])

    from .models import models
    db.create_tables(models, safe=True)

    from .hooks import before_app_request, after_app_request
    app.before_request(before_app_request)
    app.teardown_request(after_app_request)

    from .blueprints.cms_main import bp_cms_main
    from .blueprints.cms_api import bp_cms_api
    from .blueprints.open_main import bp_open_main
    from .blueprints.open_api import bp_open_api
    from .blueprints.sample_h5_main import bp_sample_h5_main
    from .blueprints.sample_h5_api import bp_sample_h5_api
    app.register_blueprint(bp_cms_main, subdomain=app.config['SUBDOMAIN'].get('cms_main'))
    app.register_blueprint(bp_cms_api, subdomain=app.config['SUBDOMAIN'].get('cms_api'), url_prefix='/api')
    app.register_blueprint(bp_open_main, subdomain=app.config['SUBDOMAIN'].get('open_main'))
    app.register_blueprint(bp_open_api, subdomain=app.config['SUBDOMAIN'].get('open_api'), url_prefix='/api')
    app.register_blueprint(bp_sample_h5_main, subdomain=app.config['SUBDOMAIN'].get('sample_h5_main'))
    app.register_blueprint(bp_sample_h5_api, subdomain=app.config['SUBDOMAIN'].get('sample_h5_api'), url_prefix='/api')

    return app


def create_celery_app(app=None):
    """
    创建celery应用对象
    :param app:
    :return:
    """
    import os
    app = app or create_app(os.getenv('FLASK_CONFIG') or 'default')
    celery = Celery(app.import_name)
    celery.conf.update(app.config)

    TaskBase = celery.Task

    class ContextTask(TaskBase):
        abstract = True

        def __call__(self, *args, **kwargs):
            with app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)

    celery.Task = ContextTask

    return celery
