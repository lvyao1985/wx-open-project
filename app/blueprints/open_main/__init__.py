# -*- coding: utf-8 -*-

from flask import Blueprint


bp_open_main = Blueprint('bp_open_main', __name__, static_folder='static')


from . import extensions
