import json
import ipaddress

event = json.loads(r"""$normalize_event.message""")
try:
    exec_data = json.loads(r"""$exec""")
except Exception:
    exec_data = {}
d = (exec_data.get("all_fields") or {}).get("data") or {}

def add(lst, value):
    if value not in (None, "", "NULL") and value not in lst:
        lst.append(value)

ip_list, public_ips, hash_list, domain_list, url_list = [], [], [], [], []

for value in (event.get("src_ip"), event.get("dst_ip")):
    try:
        ip = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        continue
    add(ip_list, str(ip))
    if ip.is_global:
        add(public_ips, str(ip))

for key in ("md5", "sha1", "sha256"):
    add(hash_list, d.get(key))
for key in ("hostname", "http_hostname", "dns_rrname"):
    add(domain_list, d.get(key))
add(url_list, d.get("url"))

print(json.dumps({
    "ip_list": ip_list,
    "public_ips": public_ips,
    "hash_list": hash_list,
    "domain_list": domain_list,
    "url_list": url_list,
    "count": len(ip_list) + len(hash_list) + len(domain_list) + len(url_list),
}))