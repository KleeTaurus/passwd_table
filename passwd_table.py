#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author: Kevin Lee
# @Date:   2017/01/20 17:11:10
# @Email:  klee.taurus@gmail.com

import string
import random
import hashlib
import uuid

from terminaltables import AsciiTable

UPPER_CHARS = string.ascii_uppercase
LOWER_CHARS = string.ascii_lowercase
SPECIAL_CHARS = '!@#$%^&*'

DEFAULT_PASSWD_LENGTH = 6
DEFAULT_HASH_LENGTH = 16


def generate_passwd(with_upper_chars=False,
                    with_lower_chars=False,
                    with_special_chars=False,
                    passwd_length=DEFAULT_PASSWD_LENGTH):
    """生成随机密码

    默认返回仅包含数字的随机密码
    :param with_upper_chars: 是否包含大写字母
    :param with_lower_chars: 是否包含小写字母
    :param with_special_chars: 是否包含特殊字符
    :param passwd_length: 密码长度
    """
    chars = string.digits

    if with_upper_chars:
        chars += UPPER_CHARS

    if with_lower_chars:
        chars += LOWER_CHARS

    if with_special_chars:
        chars += SPECIAL_CHARS

    return ''.join(random.choice(chars) for _ in range(passwd_length))


def hash_passwd(passwd, hash_length=DEFAULT_HASH_LENGTH):
    """对密码进行 hash 计算

    为了缩短 hash 后的密文长度，此处进行截断处理
    在数据量不大的情况下，依然可以确保输出结果的唯一性
    :param passwd: 原始密码
    :param hash_length: 返回 hash 后密文的长度
    """
    salt = uuid.uuid4().hex
    return hashlib.sha1(salt + passwd).hexdigest().upper()[:hash_length]


def generate_passwd_pair(with_chars=False,
                         with_special_chars=False,
                         passwd_length=None):
    """生成密码对
    """
    passwd = generate_passwd(with_upper_chars=with_chars,
                             with_lower_chars=with_chars,
                             with_special_chars=with_special_chars,
                             passwd_length=passwd_length)
    return passwd, hash_passwd(passwd)


def generate_passwd_table(repeat_times=10):
    """生成密码表

    生成密码表后需打印出来(A4纸张)，然后从计算机中彻底删除改密码表
    1. 密码映射表应始终 offline 保存，如果密码涉及重要资产建议至少存储4份。
       * 随身保存一份(随时使用)
       * 家里保存一份
       * 老婆那里保存一份
       * 最好异地存储一份(防止火灾)
    2. 线上密码管理软件中使用加密后的密文。
    """
    data = []
    data.append(['Weak', 'Normal', 'Strong'])
    for idx, passwd_length in enumerate([6, 8, 12]):
        for i in range(repeat_times):
            line = []
            for with_chars, with_special_chars in ((False, False,),
                                                   (True, False),
                                                   (True, True)):
                passwd, hashed = generate_passwd_pair(with_chars=with_chars,
                                                      with_special_chars=with_special_chars,
                                                      passwd_length=passwd_length)
                line.append('%12s : %s' % (passwd, hashed))

            data.append(line)

        if idx != 2:
            data.append(['', '', ''])

    table = AsciiTable(data)
    table.title = 'My Password Table'
    return table.table


if __name__ == '__main__':
    print(generate_passwd_table())
