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
    "req_timeout_s": 10,
    "wildcard_block": False,
    "cache": ".cache/bind_adblock",
    "blocking_mode": "NXDOMAIN",
    "lists": [],
    "domain_whitelist": [],
}

parent_dir = os.path.dirname(os.path.realpath(__file__))
main_conf_file = Path(os.path.join(parent_dir, "config.yml"))

with main_conf_file.open("r", encoding="utf8") as fconfig:
    config.update(yaml.safe_load(fconfig))

config["cache"] = Path(config["cache"])
if not config["cache"].is_absolute():
    config["cache"] = Path(parent_dir, config["cache"])

REGEX_DOMAIN = r"^\s*(?:(?:\d{1,3}\.){3}\d{1,3}|::1)\s+(?P<domain>([a-zA-Z0-9_-]+\.)+[a-zA-Z0-9_-]+)$"


def download_list(url):
    headers = {
        "User-Agent": "Bind adblock zonefile updater v1.0 (https://github.com/Trellmor/bind-adblock)",
    }
    cache = Path(config["cache"], hashlib.sha1(url.encode()).hexdigest())

    if cache.is_file():
        last_modified = datetime.fromtimestamp(cache.stat().st_mtime, tz=timezone.utc)
        headers["If-modified-since"] = eut.format_datetime(last_modified)

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
        elif req.status_code != 304:
            print(f"Unexpected status {req.status_code} downloading {url}")
    except requests.exceptions.RequestException as e:
        print(f"Error downloading {url}: {e}")

    if cache.is_file():
        with cache.open("r", encoding="utf8") as fcache:
            return fcache.read()

    return ""


def check_domain(domain, origin):
    if domain == "":
        return False

    try:
        dns.name.from_text(domain, origin)
    except DNSException:
        return False

    if not validators.domain(domain):
        if "_" in domain:
            print(f"Skipping domain with underscore (invalid for RPZ): {domain}")
        else:
            print(f"Ignoring invalid domain {domain}")
        return False

    return True


def read_list(filename):
    path = Path(filename)
    if os.path.isfile(path):
        with path.open("r", encoding="utf8") as flist:
            return flist.read()

    return ""


def parse_lists(origin):
    parsed = set()
    origin_name = dns.name.from_text(origin)
    for l in config["lists"]:
        data = None
        source_label = l.get("url") or l.get("file")
        print(f"Processing: {source_label}")

        if "url" in l:
            data = download_list(l["url"])
        elif "file" in l:
            data = read_list(l["file"])

        if data:
            raw_lines = data.splitlines()
            print(f"  Raw lines loaded: {len(raw_lines)}")

            lines = []
            ignored_empty = 0
            ignored_comment = 0
            ignored_format = 0
            ignored_invalid = 0
            matched = 0

            if l.get("format") == "infoblox":
                reader = csv.reader(io.StringIO(data))
                for row in reader:
                    if len(row) < 2:
                        ignored_format += 1
                        continue
                    domain = row[1].strip().lower()
                    lines.append(domain)

            else:
                lines = raw_lines

            for line in lines:
                domain = ""

                if re.match(r"^\s*#.*$", line):
                    ignored_comment += 1
                    continue

                # Strip inline comments
                line = re.sub(r"\s+#.*$", "", line).strip()

                if not line:
                    ignored_empty += 1
                    continue

                if l.get("format", "domain") == "hosts":
                    m = re.match(REGEX_DOMAIN, line)
                    if m:
                        domain = m.group("domain")
                    else:
                        ignored_format += 1
                        continue
                else:
                    domain = line

                domain = domain.strip()
                if check_domain(domain, origin_name):
                    parsed.add(domain)
                    matched += 1
                else:
                    ignored_invalid += 1

            print(f"  Domains matched: {matched}")
            print(
                f"  Lines ignored: {ignored_empty} empty, {ignored_comment} comment, {ignored_format} bad format, {ignored_invalid} invalid domain\n"
            )

    print(f"Total unique domains: {len(parsed)}\n")
    return parsed


def load_zone(zonefile, origin, raw):
    zone_text = ""
    path = Path(zonefile)
    tmppath = Path(config["cache"], "tempzone")

    if not path.exists():
        with tmppath.open("w", encoding="utf8") as fzone:
            fzone.write(
                f"@ 3600 IN SOA @ admin.{origin}. 0 86400 7200 2592000 86400\n@ 3600 IN NS LOCALHOST."
            )

        save_zone(tmppath, zonefile, origin, raw)

        print(
            textwrap.dedent(
                """\
                Zone file "{0}" created.

                Add BIND options entry:
                response-policy {{
                    zone "{1}";
                }};

                Add BIND zone entry:
                zone "{1}" {{
                    type master;
                    file "{0}";
                    masterfile-format {2};
                    allow-query {{ none; }};
                }};
        """
            ).format(path.resolve(), origin, "raw" if raw else "text")
        )

    if raw:
        try:
            compile_zone(zonefile, tmppath, origin, "raw", "text")
            path = tmppath
        except Exception:
            pass

    with path.open("r", encoding="utf8") as fzone:
        for line in fzone:
            zone_text += line
            if "IN NS" in line:
                break

    return dns.zone.from_text(zone_text, origin)


def update_serial(zone_name):
    soaset = zone_name.get_rdataset("@", dns.rdatatype.SOA)
    soa = soaset[0]
    if dns.version.MAJOR < 2:
        soa.serial += 1
    else:
        soaset.add(soa.replace(serial=soa.serial + 1))


def check_zone(origin, zonefile):
    cmd = ["named-checkzone", "-q", origin, str(zonefile)]
    r = subprocess.call(cmd)
    return r == 0


def rndc_reload(cmd):
    try:
        reload = subprocess.check_output(cmd, stderr=subprocess.PIPE)

    except subprocess.CalledProcessError as e:
        print(f"{e.stderr.decode(sys.getfilesystemencoding())}")
        if "multiple" in e.stderr.decode("utf-8"):
            sys.exit(
                "Please pass --views the list of configured BIND views containing origin zone."
            )
        if e.returncode != 0:
            sys.exit(f"rndc failed with return code {e.returncode}")

    print(f"{reload.decode(sys.getfilesystemencoding())}")


def reload_zone(origin, views):
    if views:
        for v in views.split():
            print(f"view {v}, {origin} ", end="", flush=True)
            rndc_reload(["rndc", "reload", origin, "IN", v])
    else:
        print(f"{origin} ", end="", flush=True)
        rndc_reload(["rndc", "reload", origin])


def compile_zone(source, target, origin, from_format, to_format):
    cmd = [
        "named-compilezone",
        "-f",
        from_format,
        "-F",
        to_format,
        "-o",
        str(target),
        origin,
        str(source),
    ]
    compilezone = subprocess.call(cmd)
    if compilezone != 0:
        raise Exception(f"named-compilezone failed with return code {compilezone}")


def save_zone(tmpzonefile1, zonefile, origin, raw):
    if raw:
        compile_zone(tmpzonefile1, zonefile, origin, "text", "raw")
    else:
        shutil.move(str(tmpzonefile1), str(zonefile))


def append_domain_to_zonefile(file, domain):
    if config["blocking_mode"] == "NXDOMAIN" or "_" in domain:
        file.write(domain + " IN CNAME .\n")
    else:
        file.write(domain + " IN A 0.0.0.0\n")
        file.write(domain + " IN AAAA ::\n")


if __name__ == "__main__":
    parser = ArgumentParser(
        description="Update zone file from public DNS ad blocking lists"
    )
    parser.add_argument(
        "--no-bind",
        dest="no_bind",
        action="store_true",
        help="Don't try to check/reload bind zone",
    )
    parser.add_argument(
        "--raw",
        dest="raw_zone",
        action="store_true",
        help="Save the zone file in raw format. Requires named-compilezone",
    )
    parser.add_argument(
        "--empty",
        dest="empty",
        action="store_true",
        help="Create header-only (empty) rpz zone file",
    )
    parser.add_argument(
        "--views",
        dest="views",
        type=str,
        help="If using multiple BIND views, list where each zone is defined",
    )
    parser.add_argument("zonefile", help="path to zone file")
    parser.add_argument("origin", help="zone origin")
    args = parser.parse_args()

    os.chdir(os.path.dirname(os.path.realpath(__file__)))

    if not config["cache"].is_dir():
        config["cache"].mkdir(parents=True)

    zone = load_zone(args.zonefile, args.origin, args.raw_zone)
    update_serial(zone)

    if args.empty:
        domains = set()
    else:
        domains = parse_lists(args.origin)

    tmpzonefile = Path(config["cache"], "tempzone")
    zone.to_file(str(tmpzonefile))

    with tmpzonefile.open("a", encoding="utf8") as f:
        for d in sorted(domains):
            if d in config["domain_whitelist"]:
                continue
            append_domain_to_zonefile(f, d)
            if config["wildcard_block"]:
                # RFC1035 validators.domain checks fail when asterisk * added
                if len(d) < 251:
                    append_domain_to_zonefile(f, "*." + d)
                else:
                    print(f"Skipping too-long wildcard: {d}")

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
