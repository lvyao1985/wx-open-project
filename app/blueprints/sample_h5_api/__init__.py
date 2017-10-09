# -*- coding: utf-8 -*-

from flask import Blueprint

from .hooks import wx_user_authentication
from ...api_utils import *


bp_sample_h5_api = Blueprint('bp_sample_h5_api', __name__)


bp_sample_h5_api.register_error_handler(APIException, handle_api_exception)
bp_sample_h5_api.register_error_handler(400, handle_400_error)
bp_sample_h5_api.register_error_handler(401, handle_401_error)
bp_sample_h5_api.register_error_handler(403, handle_403_error)
bp_sample_h5_api.register_error_handler(404, handle_404_error)
bp_sample_h5_api.register_error_handler(500, handle_500_error)
bp_sample_h5_api.before_request(before_api_request)
bp_sample_h5_api.before_request(wx_user_authentication)


from . import v_weixin, v_user
