# -*- coding: utf-8 -*-

from flask import g

from . import bp_sample_h5_api
from .decorators import login_required
from ...api_utils import *


@bp_sample_h5_api.route('/current_user/', methods=['GET'])
@login_required
def get_current_user():
    """
    获取当前微信用户详情
    :return:
    """
    data = {
        'wx_user': g.user.to_dict(g.fields)
    }
    return api_success_response(data)
