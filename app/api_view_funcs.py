# -*- coding: utf-8 -*-

from flask import request, g

from .api_utils import *


__all__ = [
    'list_objects',
    'get_object',
    'update_object_show',
    'update_object_weight',
    'delete_object',
    'delete_objects'
]


def list_objects(model, mark='objects'):
    """
    列出全部对象
    :param model:
    :param mark:
    :return:
    """
    order_by, page, per_page = map(request.args.get, ('order_by', 'page', 'per_page'))
    order_by = order_by.split(',') if order_by else None
    claim_args_digits_string(1202, *filter(None, (page, per_page)))

    data = {
        mark: [obj.to_dict(g.fields) for obj in model.iterator(None, order_by, page, per_page)],
        'total': model.count()
    }
    return api_success_response(data)


def get_object(model, _id=None, _uuid=None, mark='object'):
    """
    获取单个对象
    :param model:
    :param _id:
    :param _uuid:
    :param mark:
    :return:
    """
    obj = model.query_by_id(_id) or model.query_by_uuid(_uuid)
    claim_args(1104, obj)

    data = {
        mark: obj.to_dict(g.fields)
    }
    return api_success_response(data)


def update_object_show(model, _id=None, _uuid=None, mark='object'):
    """
    修改对象是否展示
    :param model:
    :param _id:
    :param _uuid:
    :param mark:
    :return:
    """
    show = g.json.get('show')
    obj = model.query_by_id(_id) or model.query_by_uuid(_uuid)
    claim_args(1104, obj)
    claim_args(1401, show)
    claim_args_bool(1402, show)

    data = {
        mark: obj.set_show(show).to_dict(g.fields)
    }
    return api_success_response(data)


def update_object_weight(model, _id=None, _uuid=None, mark='object'):
    """
    修改对象排序权重
    :param model:
    :param _id:
    :param _uuid:
    :param mark:
    :return:
    """
    weight = g.json.get('weight')
    obj = model.query_by_id(_id) or model.query_by_uuid(_uuid)
    claim_args(1104, obj)
    claim_args(1401, weight)
    claim_args_int(1402, weight)

    data = {
        mark: obj.set_weight(weight).to_dict(g.fields)
    }
    return api_success_response(data)


def delete_object(model, _id=None, _uuid=None):
    """
    删除单个对象
    :param model:
    :param _id:
    :param _uuid:
    :return:
    """
    obj = model.query_by_id(_id) or model.query_by_uuid(_uuid)
    claim_args(1104, obj)

    obj.delete_instance(recursive=True)
    return api_success_response({})


def delete_objects(model):
    """
    删除多个对象
    :param model:
    :return:
    """
    ids, uuids = map(request.args.get, ('ids', 'uuids'))
    claim_args_true(1601, any((ids, uuids)))
    if ids:
        ids = ids.split(',')
        claim_args_digits_string(1602, *ids)
        objects = map(model.query_by_id, ids)
    else:
        uuids = uuids.split(',')
        objects = map(model.query_by_uuid, uuids)
    claim_args(1104, *objects)

    for obj in objects:
        obj.delete_instance(recursive=True)
    return api_success_response({})
