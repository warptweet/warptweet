# Classify guest nat rules as WarpTweet publication helpers, not Docker target DNAT.
import ipaddress
import os
import re
import shutil
import subprocess
import sys


def run(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return None


def _parse_ip(value):
    value = value.strip().strip("[]")
    if "/" in value:
        value = value.split("/", 1)[0]
    try:
        addr = ipaddress.ip_address(value)
        if getattr(addr, "ipv4_mapped", None):
            addr = addr.ipv4_mapped
        return addr
    except Exception:
        return None


def spec_from_env(env):
    def port(name):
        raw = (env.get(name) or "").strip()
        if not raw:
            return None
        try:
            value = int(raw)
        except ValueError:
            return None
        if value < 1 or value > 65535:
            return None
        return value

    def host(name):
        raw = (env.get(name) or "").strip()
        if not raw:
            return None
        addr = _parse_ip(raw)
        if addr is None or addr.is_unspecified:
            return None
        return addr

    data_port = port("WT_DATA_PORT")
    enroll_port = port("WT_ENROLL_PORT")
    advertise_port = port("WT_ADVERTISE_PORT") or data_port
    enroll_advertise_port = port("WT_ENROLL_ADVERTISE_PORT") or enroll_port
    target_port = port("WT_TARGET_PORT") or 5432
    ports = {item for item in (data_port, enroll_port, advertise_port, enroll_advertise_port) if item}
    addrs = {
        item
        for item in (
            host("WT_LISTEN_HOST"),
            host("WT_ADVERTISE_HOST"),
            host("WT_ENROLL_LISTEN_HOST"),
            host("WT_ENROLL_ADVERTISE_HOST"),
        )
        if item is not None
    }
    return {"ports": ports, "addrs": addrs, "target_port": target_port}


def _ints(values):
    out = set()
    for value in values:
        try:
            number = int(value)
        except (TypeError, ValueError):
            continue
        if 1 <= number <= 65535:
            out.add(number)
    return out


def _hosts(values):
    out = set()
    for value in values:
        addr = _parse_ip(value)
        if addr is not None:
            out.add(addr)
    return out


def parse_iptables_rule(line):
    if not re.search(r"\s-j\s+(DNAT|REDIRECT|NETMAP)\b", line):
        return None
    dports = _ints(re.findall(r"--dport(?:s)?\s+(\d+)", line))
    to_ports = _ints(re.findall(r"--to-ports?\s+(\d+)", line))
    daddrs = _hosts(re.findall(r"\s-d\s+(\S+)", line))
    to_addrs = set()
    for dest in re.findall(r"--to-destination\s+(\S+)", line):
        if dest.startswith("["):
            match = re.match(r"\[([^\]]+)\](?::(\d+))?$", dest)
            if match:
                to_addrs |= _hosts([match.group(1)])
                to_ports |= _ints([match.group(2)] if match.group(2) else [])
            continue
        if re.search(r":\d+$", dest):
            host, port = dest.rsplit(":", 1)
            to_addrs |= _hosts([host])
            to_ports |= _ints([port])
            continue
        to_addrs |= _hosts([dest])
    return {"dports": dports, "to_ports": to_ports, "daddrs": daddrs, "to_addrs": to_addrs}


def parse_nft_rule(line):
    if not re.search(r"\b(dnat|redirect)\b", line, re.I):
        return None
    dports = _ints(re.findall(r"\bdport\s+(\d+)", line))
    daddrs = _hosts(re.findall(r"\bdaddr\s+(\S+)", line))
    to_ports = set()
    to_addrs = set()
    match = re.search(r"\b(?:dnat|redirect)(?:\s+\S+)?\s+to\s+(\S+)", line, re.I)
    if match:
        dest = match.group(1).rstrip(";")
        if dest.startswith("["):
            inner = re.match(r"\[([^\]]+)\](?::(\d+))?", dest)
            if inner:
                to_addrs |= _hosts([inner.group(1)])
                to_ports |= _ints([inner.group(2)] if inner.group(2) else [])
        elif re.search(r":\d+$", dest):
            host, port = dest.rsplit(":", 1)
            to_addrs |= _hosts([host])
            to_ports |= _ints([port])
        else:
            to_addrs |= _hosts([dest])
            to_ports |= _ints(re.findall(r"\bto\s+port\s+(\d+)", line))
    to_ports |= _ints(re.findall(r"\bredirect\s+to\s+(?:port\s+)?(\d+)", line, re.I))
    return {"dports": dports, "to_ports": to_ports, "daddrs": daddrs, "to_addrs": to_addrs}


def rule_rewrites_publication(parsed, spec):
    if parsed is None:
        return False
    pub_ports = spec["ports"]
    pub_addrs = spec["addrs"]
    if parsed["dports"] & pub_ports or parsed["to_ports"] & pub_ports:
        return True
    if parsed["daddrs"] & pub_addrs or parsed["to_addrs"] & pub_addrs:
        return True
    return False


def has_publication_dnat(text, spec, kind):
    if not text:
        return False
    parse = parse_iptables_rule if kind == "iptables" else parse_nft_rule
    for line in text.splitlines():
        if rule_rewrites_publication(parse(line), spec):
            return True
    return False


def table_status(dump, spec, kind, present):
    if not present:
        return "MISSING"
    if dump is None:
        return "MISSING"
    if has_publication_dnat(dump, spec, kind):
        return "HAS_DNAT"
    return "NO_DNAT"


def live_table_status(spec):
    iptables_present = shutil.which("iptables") is not None
    nft_present = shutil.which("nft") is not None
    iptables_dump = run(["iptables", "-t", "nat", "-S"]) if iptables_present else None
    nft_dump = run(["nft", "list", "ruleset"]) if nft_present else None
    return (
        table_status(iptables_dump, spec, "iptables", iptables_present),
        table_status(nft_dump, spec, "nft", nft_present),
    )


def self_test():
    spec = {
        "ports": {2222, 29722},
        "addrs": {_parse_ip("10.168.0.2"), _parse_ip("34.20.174.226")},
        "target_port": 5432,
    }
    docker = """
-A DOCKER -d 127.0.0.1/32 ! -i docker0 -p tcp -m tcp --dport 5432 -j DNAT --to-destination 172.17.0.2:5432
-A POSTROUTING -s 172.17.0.2/32 -d 172.17.0.2/32 -p tcp --dport 5432 -j MASQUERADE
"""
    if has_publication_dnat(docker, spec, "iptables"):
        raise AssertionError("docker loopback postgres DNAT must not count")
    if table_status(docker, spec, "iptables", True) != "NO_DNAT":
        raise AssertionError("docker postgres must be NO_DNAT")
    helper = "-A PREROUTING -d 34.20.174.226/32 -p tcp --dport 2222 -j DNAT --to-destination 10.168.0.2:2222\n"
    if not has_publication_dnat(helper, spec, "iptables"):
        raise AssertionError("advertise-port DNAT must count")
    enroll = "-A PREROUTING -p tcp --dport 29722 -j REDIRECT --to-ports 29722\n"
    if not has_publication_dnat(enroll, spec, "iptables"):
        raise AssertionError("enrollment REDIRECT must count")
    mapped = "-A PREROUTING -d 34.20.174.226/32 -j DNAT --to-destination 127.0.0.1\n"
    if not has_publication_dnat(mapped, spec, "iptables"):
        raise AssertionError("advertise-address map onto guest must count")
    nft_docker = "ip daddr 127.0.0.1 tcp dport 5432 dnat to 172.17.0.2:5432\n"
    if has_publication_dnat(nft_docker, spec, "nft"):
        raise AssertionError("nft docker 5432 dnat must not count")
    nft_helper = "ip daddr 34.20.174.226 tcp dport 2222 dnat to 10.168.0.2:2222\n"
    if not has_publication_dnat(nft_helper, spec, "nft"):
        raise AssertionError("nft advertise-port dnat must count")
    if table_status("", spec, "iptables", True) != "NO_DNAT":
        raise AssertionError("empty nat table is NO_DNAT")
    if table_status(None, spec, "nft", True) != "MISSING":
        raise AssertionError("failed nft dump is MISSING")
    print("publication_dnat_self_test_ok")


if __name__ == "__main__" and sys.argv[0] != "-" and sys.argv[1:] == ["--self-test"]:
    self_test()
    raise SystemExit(0)
