# -*- coding: utf-8 -*-

from flask import current_app, jsonify

from . import bp_h5_main
from utils.qiniu_util import get_upload_token


@bp_h5_main.route('/extensions/qn/upload_token/', methods=['GET'])
def get_qn_upload_token():
    """
    获取七牛上传凭证
    :return:
    """
    data = {
        'uptoken': get_upload_token(current_app.config['QINIU'])
    }
    return jsonify(data)
