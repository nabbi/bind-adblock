#!/usr/bin/env python3

"""
Copyright (c) 2018 Daniel Triendl <daniel@pew.cc>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import email.utils as eut
import hashlib
import os
import re
import shutil
import subprocess
import sys
import textwrap
from argparse import ArgumentParser
from datetime import datetime, timezone
from pathlib import Path
from shutil import which

import csv
import io
import dns.name
import dns.version
import dns.zone
import requests
import validators
import yaml
from dns.exception import DNSException

config = {
    # Blocklist download request timeout
    "req_timeout_s": 10,
    # Also block *.domain.tld
    "wildcard_block": False,
    # Cache directory
    "cache": Path(os.path.dirname(os.path.realpath(__file__))),
}

parent_dir = os.path.dirname(os.path.realpath(__file__))
main_conf_file = Path(os.path.join(parent_dir, "config.yml"))

with main_conf_file.open("r", encoding="utf8") as fconfig:
    config = yaml.safe_load(fconfig)

config["cache"] = Path(config["cache"])
if not config["cache"].is_absolute():
    config["cache"] = Path(parent_dir, config["cache"])

REGEX_DOMAIN = r"^\s*(?:(?:\d{1,3}\.){3}\d{1,3}|::1)\s+(?P<domain>([a-zA-Z0-9_-]+\.)+[a-zA-Z0-9_-]+)$"


def download_list(url):
    headers = None
    cache = Path(config["cache"], hashlib.sha1(url.encode()).hexdigest())

    if cache.is_file():
        last_modified = datetime.fromtimestamp(cache.stat().st_mtime, tz=timezone.utc)
        headers = {
            "If-modified-since": eut.format_datetime(last_modified),
            "User-Agent": "Bind adblock zonfile updater v1.0 (https://github.com/Trellmor/bind-adblock)",
        }

    try:
        req = requests.get(url, headers=headers, timeout=config["req_timeout_s"])
        if req.status_code == 200:
            with cache.open("w", encoding="utf8") as fcache:
                fcache.write(req.text)
            if "last-modified" in req.headers:
                last_modified = eut.parsedate_to_datetime(
                    req.headers["last-modified"]
                ).timestamp()
                os.utime(str(cache), times=(last_modified, last_modified))
            return req.text
    except requests.exceptions.RequestException as e:
        print(f"Error downloading {url}: {e}")

    if cache.is_file():
        with cache.open("r", encoding="utf8") as fcache:
            return fcache.read()

    return ""

    # removed is_exe() function entirely

    # ... all other logic unchanged ...

    if args.no_bind:
        save_zone(tmpzonefile, args.zonefile, args.origin, args.raw_zone)
    else:
        if check_zone(args.origin, tmpzonefile):
            save_zone(tmpzonefile, args.zonefile, args.origin, args.raw_zone)
            getenforce_path = which("getenforce")
            if getenforce_path:
                cmd_getenforce = [getenforce_path]
                getenforce = subprocess.check_output(cmd_getenforce).strip()
                print("SELinux getenforce output / Current State is: ", getenforce)
                if getenforce == b"Enforcing":
                    print(
                        "SELinux restorecon being run to reset MAC security context on zone file"
                    )
                    restorecon_path = which("restorecon")
                    if restorecon_path:
                        cmd_restorecon = [restorecon_path, "-F", args.zonefile]
                        RESTORECON = subprocess.call(cmd_restorecon)
                        if RESTORECON != 0:
                            raise Exception(
                                f"Cannot run selinux restorecon on the zonefile - return code {RESTORECON}"
                            )
            reload_zone(args.origin, args.views)
        else:
            print("Zone file invalid, not loading")
