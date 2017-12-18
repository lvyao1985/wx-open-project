## API Overview

**All data is sent and received as JSON.**

**success response**

    {
        code: 0
        message: 'Success'
        data: {
            [响应数据]
        }
    }

**error response**

    {
        code: [错误码]
        message: [错误信息]
        data: {}
    }

**错误码对应错误信息**

    1000: 'Internal Server Error'
    1100: 'Bad Request'
    1101: 'Unauthorized'
    1103: 'Forbidden'
    1104: 'Not Found'
    1201: 'GET方法url参数不完整'
    1202: 'GET方法url参数值错误'
    1401: 'POST/PUT方法json数据不完整'
    1402: 'POST/PUT方法json数据值或类型错误'
    1601: 'DELETE方法url参数不完整'
    1602: 'DELETE方法url参数值错误'
    1800: '微信开放平台接口调用失败'
    1810: '微信公众平台接口调用失败'
    1850: '七牛上传凭证获取失败'
    1851: '七牛上传二进制流失败'
    1852: '七牛上传文件失败'

**某些情况下通用的错误码**

    所有请求：1000
    POST/PUT方法：1100
    login_required访问限制：1101
    使用分页参数page/per_page：1202

**通用的可选URL参数**

    fields: 指定返回的对象数据中只包含哪些字段，多个字段以英文逗号分隔

## API References

**获取微信JS-SDK权限验证配置**

    GET  /api/wx/js_sdk_config/

    必填URL参数：
        url: 使用JS-SDK的页面URL，不包含#及其后面部分

    响应数据：
        appid [string]:
        noncestr [string]:
        signature [string]:
        timestamp [int]:

    错误码：
        1201, 1810

**获取当前微信用户详情**
_(login_required)_

    GET  /api/current_user/

    响应数据：
        wx_user [object]:

## Extensions

**获取七牛上传凭证**

    GET  /extensions/qn/upload_token/

**微信公众号网页授权**

    GET  /extensions/wx/user/authorize/

    可选URL参数：
        state: 授权后跳转到的页面路径，默认为根目录；须进行URL编码处理

**微信用户登录（测试）**

    GET  /extensions/testing/wx/user/<uuid:wx_user_uuid>/login/

    可选URL参数：
        state: 登录后跳转到的页面路径，默认为根目录；须进行URL编码处理

**微信用户退出（测试）**

    GET  /extensions/testing/wx/user/logout/

    可选URL参数：
        state: 退出后跳转到的页面路径，默认为根目录；须进行URL编码处理

## Model Dependencies

_- : on_delete='CASCADE'_

_* : on_delete='CASCADE', null=True_
