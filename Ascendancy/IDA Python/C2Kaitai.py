#!/usr/bin/env python

import yaml
import re
import sys

TYPE_TO_KSY = {
    'uint8_t': 'u1',
    'uint16pippip_t': 'u2',
    'uint32_t': 'u4',
    'uint64_t': 'u8',

    'int8_t': 's1',
    'int16_t': 's2',
    'int32_t': 's4',
    'int64_t': 's8',

    'char': 's1',
    'short': 's2',
    'int': 's4',
    'uint': 'u4',
    'long': 's8',
    'float': 'f4',
    'double': 'f8',

    'WORD': 'u2',
    'DWORD': 'u4',

    '__s32': 's4',
    '__s64': 's8',
}

def parse_body(body):
    r = []

    pattern = re.compile(r'\s*([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s*;\s*(\/\*\s*(.*?)\s*\*\/)?')
    for match in pattern.finditer(body):
        type, name, comment, comment_body = match.groups()
        h = {'id': name, 'type': TYPE_TO_KSY.get(type, type)}
        if comment_body and comment_body.strip():
            h['doc'] = comment_body
        r.append(h)
    return r

r = {}

input_data = sys.stdin.read()
pattern = re.compile(r'struct\s+([A-Za-z0-9_]+)?\s*\{(.*?)\}\s*(.*?);', re.DOTALL)
for match in pattern.finditer(input_data):
    tag, body, name = match.groups()
    name = name.split(',')[0].strip()
    name = tag if not name else name
    r[name] = parse_body(body)

print(yaml.dump({'types': r}))

