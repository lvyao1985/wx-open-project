# -*- coding: utf-8 -*-

from flask import Blueprint


bp_sample_h5_main = Blueprint('bp_sample_h5_main', __name__, static_folder='static')


from . import extensions
