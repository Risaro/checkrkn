import datetime as dt
import ipaddress
import json
import pathlib
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
CACHE = ROOT / "cache"
OUT = ROOT / "lists"
UA = "checkrkn-builder/1.0"
RECENT_DAYS = 30
MIN_PREFIX_V4 = 12
MIN_PREFIX_V6 = 24
WIDE_OK = {"spamhaus_drop_v4", "spamhaus_drop_v6"}

SAFE = [
    ("rkn_scanners", "https://gist.githubusercontent.com/sngvy/07cee7ac810c9d222fbebddff8c1d1b8/raw/blacklist.txt", "text"),
    ("isc_research", "https://isc.sans.edu/api/threatcategory/research?json", "isc"),
    ("spamhaus_drop_v4", "https://www.spamhaus.org/drop/drop_v4.json", "ndjson"),
    ("spamhaus_drop_v6", "https://www.spamhaus.org/drop/drop_v6.json", "ndjson"),
    ("dshield_top", "https://feeds.dshield.org/block.txt", "dshield"),
    ("et_block", "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt", "text"),
    ("feodo_c2", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "text"),
]
AGGRESSIVE = [
    ("ipsum_l3", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", "text"),
    ("cins_badguys", "https://cinsscore.com/list/ci-badguys.txt", "text"),
    ("binarydefense", "https://www.binarydefense.com/banlist.txt", "text"),
]
RIPE_DELEGATED = "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest"
SPARE_COUNTRIES = {"RU"}
NEVER = [
    ("cloudflare_v4", "https://www.cloudflare.com/ips-v4", "text"),
    ("cloudflare_v6", "https://www.cloudflare.com/ips-v6", "text"),
]
NEVER_STATIC = ["1.1.1.1/32", "1.0.0.1/32", "8.8.8.8/32", "8.8.4.4/32", "9.9.9.9/32", "77.88.8.8/32", "77.88.8.1/32"]


def fetch(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def net(token):
    token = token.strip()
    if not token:
        return None
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None


def parse(kind, body):
    out = []
    if kind == "text":
        for line in body.splitlines():
            line = line.split("#", 1)[0].split(";", 1)[0].strip()
            if not line:
                continue
            n = net(line.split()[0])
            if n:
                out.append(n)
    elif kind == "ndjson":
        for line in body.splitlines():
            try:
                n = net(json.loads(line).get("cidr", ""))
            except (ValueError, AttributeError):
                n = None
            if n:
                out.append(n)
    elif kind == "dshield":
        for line in body.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) >= 3 and parts[0][0].isdigit():
                n = net(f"{parts[0]}/{parts[2]}")
                if n:
                    out.append(n)
    elif kind == "isc":
        cutoff = (dt.date.today() - dt.timedelta(days=RECENT_DAYS)).isoformat()
        for item in json.loads(body):
            seen = item.get("lastseen") or item.get("added") or ""
            if seen and seen < cutoff:
                continue
            n = net(item.get("ipv4") or item.get("ipv6") or "")
            if n:
                out.append(n)
    return out


def load_source(name, url, kind):
    cache = CACHE / f"{name}.txt"
    try:
        nets = parse(kind, fetch(url))
        if not nets:
            raise ValueError("empty")
        cache.write_text("\n".join(str(n) for n in nets) + "\n")
        return nets, "fresh"
    except Exception as exc:
        if cache.exists():
            return [n for n in (net(x) for x in cache.read_text().splitlines()) if n], f"cache ({type(exc).__name__})"
        return [], f"failed ({type(exc).__name__})"


def ripe_country_nets(countries):
    cache = CACHE / "ripe_spare.txt"
    try:
        body = fetch(RIPE_DELEGATED, timeout=120)
        nets = []
        for line in body.splitlines():
            p = line.split("|")
            if len(p) < 7 or p[1] not in countries or p[2] not in ("ipv4", "ipv6"):
                continue
            if p[2] == "ipv4":
                start = ipaddress.IPv4Address(p[3])
                end = start + int(p[4]) - 1
                nets.extend(ipaddress.summarize_address_range(start, end))
            else:
                nets.append(ipaddress.ip_network(f"{p[3]}/{p[4]}"))
        if len(nets) < 1000:
            raise ValueError("too few")
        cache.write_text("\n".join(str(n) for n in ipaddress.collapse_addresses([n for n in nets if n.version == 4])) + "\n"
                         + "\n".join(str(n) for n in ipaddress.collapse_addresses([n for n in nets if n.version == 6])) + "\n")
        return nets, "fresh"
    except Exception as exc:
        if cache.exists():
            return [n for n in (net(x) for x in cache.read_text().splitlines()) if n], f"cache ({type(exc).__name__})"
        return None, f"failed ({type(exc).__name__})"


def bad_scope(n):
    return n.is_private or n.is_loopback or n.is_link_local or n.is_multicast or n.is_reserved or n.is_unspecified


def wide(n, name):
    limit = MIN_PREFIX_V4 if n.version == 4 else MIN_PREFIX_V6
    if n.prefixlen >= limit:
        return False
    return name not in WIDE_OK or n.prefixlen < 8


def subtract(nets, holes):
    by_ver = {4: [], 6: []}
    for h in holes:
        by_ver[h.version].append(h)
    for v in by_ver:
        by_ver[v] = list(ipaddress.collapse_addresses(by_ver[v]))
    result = []
    for n in nets:
        parts = [n]
        for h in by_ver[n.version]:
            nxt = []
            for p in parts:
                if p.subnet_of(h):
                    continue
                if h.subnet_of(p):
                    nxt.extend(p.address_exclude(h))
                else:
                    nxt.append(p)
            parts = nxt
            if not parts:
                break
        result.extend(parts)
    return result


def overlapping(nets, holes):
    import bisect
    keep = []
    for v in (4, 6):
        hs = list(ipaddress.collapse_addresses([h for h in holes if h.version == v]))
        starts = [int(h.network_address) for h in hs]
        ends = [int(h.broadcast_address) for h in hs]
        for n in (x for x in nets if x.version == v):
            i = bisect.bisect_right(starts, int(n.broadcast_address)) - 1
            keep.append((n, i >= 0 and ends[i] >= int(n.network_address)))
    return keep


def main():
    CACHE.mkdir(exist_ok=True)
    OUT.mkdir(exist_ok=True)
    stats = {"built_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(), "sources": {}}

    never = [net(x) for x in NEVER_STATIC]
    for name, url, kind in NEVER:
        nets, state = load_source(name, url, kind)
        never.extend(nets)
        stats["sources"][name] = {"role": "never_block", "count": len(nets), "state": state}

    safe = []
    for name, url, kind in SAFE:
        nets, state = load_source(name, url, kind)
        good = [n for n in nets if not bad_scope(n) and not wide(n, name)]
        safe.extend(good)
        stats["sources"][name] = {"role": "safe", "count": len(good), "state": state}

    spare, spare_state = ripe_country_nets(SPARE_COUNTRIES)
    stats["sources"]["ripe_spare"] = {"role": "spare_countries", "countries": sorted(SPARE_COUNTRIES),
                                      "count": len(spare or []), "state": spare_state}
    aggressive = []
    for name, url, kind in AGGRESSIVE:
        nets, state = load_source(name, url, kind)
        good = [n for n in nets if not bad_scope(n) and not wide(n, name)]
        if spare is None:
            stats["sources"][name] = {"role": "aggressive", "count": 0, "state": state + "; skipped: no country data"}
            continue
        kept = [n for n, hit in overlapping(good, spare) if not hit]
        aggressive.extend(kept)
        stats["sources"][name] = {"role": "aggressive", "count": len(kept), "dropped_spared": len(good) - len(kept), "state": state}

    allnets = subtract(safe + aggressive, never)
    v4 = list(ipaddress.collapse_addresses([n for n in allnets if n.version == 4]))
    v6 = list(ipaddress.collapse_addresses([n for n in allnets if n.version == 6]))
    if len(v4) < 1000:
        print(f"refusing to write: only {len(v4)} v4 entries", file=sys.stderr)
        sys.exit(1)

    stats["total_v4"] = len(v4)
    stats["total_v6"] = len(v6)
    stats["total_v4_addresses"] = sum(n.num_addresses for n in v4)
    header = [f"# checkrkn blocklist, built {stats['built_at']}", f"# v4={len(v4)} v6={len(v6)}"]
    (OUT / "blocklist.txt").write_text("\n".join(header + [str(n) for n in v4] + [str(n) for n in v6]) + "\n")
    safe_v4 = list(ipaddress.collapse_addresses([n for n in subtract(safe, never) if n.version == 4]))
    safe_v6 = list(ipaddress.collapse_addresses([n for n in subtract(safe, never) if n.version == 6]))
    (OUT / "blocklist-safe.txt").write_text("\n".join([f"# checkrkn safe blocklist, built {stats['built_at']}"]
                                                     + [str(n) for n in safe_v4] + [str(n) for n in safe_v6]) + "\n")
    (OUT / "stats.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(stats, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
