# -*- coding: utf-8 -*-

from flask import request, g, abort

from ...models import Admin


def admin_authentication():
    """
    管理员身份认证
    :return:
    """
    if request.endpoint.split('.')[-1] in ['login']:
        return

    token = request.environ.get('HTTP_AUTHORIZATION')
    if token:
        g.admin = Admin.query_by_token(token)  # g.admin
        if g.admin:
            return

    abort(401)
