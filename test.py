#!/usr/bin/env python3

# Install deps:
#   apt install python3.8 python3.8-pip
#   python3.8 -m pip install timeout_decorator appdirs dataclasses

# Run this:
#   python3.8 test.py -f test/klay-0x68da33c27a898796e6dcbb9617a34f78c3ec7a55.txt

import argparse
import sys
import json
import logging

from panoramix import decompiler

def deco_code(code):
    code = code.strip()
    ctr = decompiler.decompile_bytecode(code)
    d = dict()
    d['asm'] = '\n'.join(ctr.asm)
    d['pseudocode'] = ctr.text
    d['functions'] = ctr.json['functions']
    d['storages'] = ctr.json['stor_defs']
    return d

def deco(args):
    if args.file:
        d = deco_code(args.file.read())
    elif args.stdin:
        d = deco_code(sys.stdin.read())
    args.output.write(json.dumps(d))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('-f', '--file', type=argparse.FileType('r'), help='bytecode file in hex')
    source.add_argument('-i', '--stdin', action='store_true', help='read bytecode in hex from stdin')
    parser.add_argument('-o', '--output', type=argparse.FileType('w'),
            help='output json file', default="out.json")

    args = parser.parse_args()

    logging.getLogger("panoramix.matcher").setLevel(logging.DEBUG)
    deco(args)

