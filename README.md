# BIND ad blocker

Fetch various blocklists and generate a BIND zone from them.

Configure BIND to return `NXDOMAIN` for ad and tracking domains or optionally sinkhole them to `0.0.0.0`/`::` depending on configuration.

Requires BIND 9.8 or newer for [RPZ](https://en.wikipedia.org/wiki/Response_policy_zone) support.

Uses (by default) the following sources, as defined in `config.yml`:

* Optional local blocklist file (`blocklist.txt`)
* [Peter Lowe’s Ad and tracking server list](https://pgl.yoyo.org/adservers/)
* [MVPS HOSTS](http://winhelp2002.mvps.org/)
* [Adaway default blocklist](https://adaway.org/hosts.txt)
* [Dan Pollock’s hosts file](https://www.someonewhocares.org/hosts/zero/)
* [StevenBlack Unified hosts file](https://github.com/StevenBlack/hosts)
* [CAMELEON](http://sysctl.org/cameleon/)
* [Disconnect.me Basic tracking list](https://disconnect.me/trackerprotection)
* [Disconnect.me Ad Filter list](https://disconnect.me/trackerprotection)
* [Polish CERT Phishing list](https://www.cert.pl/ostrzezenia_phishing/)
* [Phishing Domains Blocklist (malware-filter)](https://gitlab.com/malware-filter/phishing-filter)
* [HaGeZi's Fake DNS Blocklist](https://github.com/hagezi/dns-blocklists)
* [HaGeZi's Ultimate DNS Blocklist](https://github.com/hagezi/dns-blocklists)
* [InfobloxOpen Threat Intelligence](https://github.com/infobloxopen/threat-intelligence)
* [Blocklist Project (malware, ransomware, scam, ads)](https://blocklistproject.github.io/Lists/)

See the supplied `config.yml` to view or modify the exact lists.

---

## Setup

### Python packages

See **requirements.txt**.

To install:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

### Configuration (`config.yml`)

The script is controlled by the `config.yml` file in the same directory.
Common options include:

* **req_timeout_s**: HTTP timeout for blocklist downloads
* **wildcard_block**: If `true`, also block `*.domain.tld`
* **cache**: Directory for downloaded lists and temporary files
* **blocking_mode**:

  * `NXDOMAIN` — return NXDOMAIN via `CNAME .`
  * *any other value* — sinkhole mode (`A 0.0.0.0`, `AAAA ::`)
* **lists**: Blocklists to load (each entry may be `url:` or `file:`) with optional `format:`:

  * `domain` — one domain per line (default)
  * `hosts` — hosts-format `IP domain`
  * `infoblox` — Infoblox CSV, domain taken from second column
* **domain_whitelist**: Domains that must never be blocked

Review `config.yml` for active lists and format definitions.

---

## Configure BIND

Add the `response-policy` statement to BIND options:

```bash
// For AdBlock
response-policy {
    zone "rpz.example.com";
};
```

Add your RPZ zone. Replace `example.com` with the domain of your choice.

```bash
// AdBlock
zone "rpz.example.com" {
    type master;
    file "/etc/bind/db.rpz.example.com";
    masterfile-format text;
    allow-query { none; };
};
```

Create the initial zone file for your RPZ:

```text
@ 3600 IN SOA @ admin.example.com. 0 86400 7200 2592000 86400
@ 3600 IN NS LOCALHOST.
```

(Any valid NS record is acceptable.)

---

## Usage

```text
usage: update-zonefile.py [-h] [--no-bind] [--raw] [--empty] [--views VIEWS]
                          zonefile origin

Update zone file from public DNS ad blocking lists

positional arguments:
  zonefile    path to zone file
  origin      zone origin

optional arguments:
  -h, --help  show this help message and exit
  --no-bind   Don't try to check/reload bind zone
  --raw       Save the zone file in raw format. Requires named-compilezone
  --empty     Create header-only (empty) rpz zone file
  --views     If using multiple BIND views, list where each zone is defined
```

Example:

```bash
update-zonefile.py /etc/bind/db.rpz.example.com rpz.example.com
```

`update-zonefile.py` will update the zone file using the configured blocklists,
validate it using `named-checkzone`, optionally restore SELinux file context if enforcing,
and finally run:

```bash
rndc reload origin
```

---

### Multiple BIND Views

If you defined the RPZ zone inside multiple views, pass a space‑separated list of those views:

```bash
--views "internal dmz test"
```

The script will run `rndc reload origin IN view` for each provided view.

If you forget this and the zone exists in multiple views, BIND will report:

```text
zone 'rpz.adblocker' was found in multiple views
```

---

## Whitelist

You may whitelist domains by:

* Adding them to `domain_whitelist` in `config.yml`, or
* Creating a separate whitelist RPZ zone.

See the project's Wiki page on **Whitelist** for details.
