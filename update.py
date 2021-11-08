#!/usr/bin/env python3
# -*- mode: python; -*-
import json
import argparse
import logging
import sys
import re
import configparser
from collections import defaultdict
import os.path
from urllib import request
import base64
import copy
import time
import subprocess
import traceback
import platform
import socket
import tempfile
import zipfile

__VERSION__ = '0.1'

default_logging_level = logging.INFO

class GFWException(Exception):
    pass


class Logger():
    def __init__(self, name):
        logformat = '%(asctime)s %(name)s: %(levelname)s [%(funcName)s/%(lineno)d] %(message)s'
        self.logger = logging.getLogger(name)
        self.logger.setLevel(default_logging_level)
        if not self.logger.handlers:
            myhandler = logging.StreamHandler(stream=sys.stdout)
            myhandler.setFormatter(logging.Formatter(logformat))
            self.logger.addHandler(myhandler)

class Updater(object):
    def __init__(self, output, dns, ipset, extra, exclude):
        self.logger = Logger(self.__class__.__name__).logger
        self.logger.debug('init')
        self.url = 'https://raw.github.com/gfwlist/gfwlist/master/gfwlist.txt'
        self.filename = output
        self.dns = dns
        self.ipset = ipset
        self.extra = extra
        self.exclude = {}

        if exclude:
            for domain in exclude.read().splitlines():
                self.exclude[domain] = True

    def _update_list_file_from_remote(self, url, filename):
        resp = request.urlopen(url)
        if resp.status == 200:
            data = base64.b64decode(resp.read())
            with open(filename, 'wb') as fh:
                return fh.write(data)
        return 0

    def _process_gfw_list(self, content):
        ret = set()
        data = base64.b64decode(content).decode('utf8')
        regexs = [
            [r'^!.*$|^@@.*$|^\[AutoProxy.*$', '', re.IGNORECASE | re.M],
            [r'^\|\|?|\|$', '', re.M],  # ||
            [r'^https?:/?/?', '', re.IGNORECASE | re.M],  # https://
            [r'(/|%).*$', '', re.M],  # url path
            [r'[^.\n]*\*[^.\n]*\.?', '', re.M],  # abc*abc.
            [r'^\*?\.|^.*\.\*?$', '', re.M],  # *. or .*
            [r'^\d+\.\d+\.\d+\.\d+(:\d+)?$', '', re.M],  # ip:port
            [r'^[^.]*[.]*$', '', re.M],  # lines not include .
        ]
        for regex in regexs:
            (pattern, replace, flags) = regex
            data = re.sub(pattern, replace, data, flags=flags)
        for domain in data.split("\n"):
            if domain:
                ret.add(domain)
        return ret

    def _update_gfw_list(self, url, filename):
        self.logger.debug('start update gfwlist')
        resp = request.urlopen(url)
        if resp.status == 200:
            domains = self._process_gfw_list(resp.read())

        self.logger.debug('fetched {} domains from remote'.format(len(domains)))
        ext_filename = filename + '.ext'
        if self.extra:
            lines = self.extra.read().splitlines()
            self.logger.debug('process ext file, include {} lines'.format(len(lines)))
            for domain in lines:
                if re.match(r'^$|^#.*$', domain):
                    continue
                domains.add(domain)

        with open(filename, 'w') as fh:
            for domain in domains:
                if self.exclude.get(domain, False):
                    continue
                fh.write("server=/{}/{}\n".format(domain, self.dns))
                fh.write("ipset=/{}/{}\n".format(domain, self.ipset))

        self.logger.info('total domain {}'.format(len(domains)))

    def update_list(self):
        self._update_gfw_list(self.url, self.filename)


def main():
    main_parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description='Simple gfwlist ipset updater, version {}'.format(__VERSION__)
    )

    main_parser.add_argument('--verbose', '-v', help='Show verbose messages', action="store_true", default=False)
    main_parser.add_argument('--dns', '-d', help='dns ip', default="8.8.8.8", type=str)
    main_parser.add_argument('--ipset', '-i', help='ipset list name', default="gfwip", type=str)
    main_parser.add_argument('--output', '-o', help='output file', type=str, default="gfwlist-ipset.conf")
    main_parser.add_argument('--extra', '-e', help='extra domain names', type=open)
    main_parser.add_argument('--exclude', '-k', help='exclude domain names', type=open)

    logger = Logger('Main').logger
    opts = main_parser.parse_args()
    if opts.verbose:
        global default_logging_level
        default_logging_level = logging.DEBUG
        logger.setLevel(default_logging_level)

    Updater(output=opts.output, dns=opts.dns, ipset=opts.ipset, extra=opts.extra, exclude=opts.exclude).update_list()

if __name__ == '__main__':
    main()
