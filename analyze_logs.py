"""Пошук і аналіз журналу брандмауера.
Приклади:
  python analyze_logs.py logs/events.jsonl                         # статистика і аномалії
  python analyze_logs.py logs/events.jsonl --action deny            # усі заблоковані
  python analyze_logs.py logs/events.jsonl --proto UDP --rule 2     # UDP, заблоковані правилом 2
  python analyze_logs.py logs/events.jsonl --src 127.0.0.1 --since 2026-11-11T18:00:00Z"""
import argparse, json, collections, ipaddress


def match(e, a):
    if a.event and not e['event'].startswith(a.event): return False
    if a.action and e.get('action') != a.action: return False
    if a.proto and e.get('proto') != a.proto.upper(): return False
    if a.rule is not None and e.get('rule_id') != a.rule: return False
    if a.dst_port and (e.get('dst') or [None, None])[1] != a.dst_port: return False
    if a.src:
        if not e.get('src'): return False
        if ipaddress.ip_address(e['src'][0]) not in ipaddress.ip_network(a.src, strict=False): return False
    if a.since and e['ts'] < a.since: return False
    if a.until and e['ts'] > a.until: return False
    return True


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('path', nargs='?', default='logs/events.jsonl')
    ap.add_argument('--event', help='prefix: tcp, udp, rule')
    ap.add_argument('--action', choices=['allow', 'deny'])
    ap.add_argument('--proto', choices=['TCP', 'UDP', 'tcp', 'udp'])
    ap.add_argument('--src', help='source IP or CIDR')
    ap.add_argument('--dst-port', type=int)
    ap.add_argument('--rule', type=int, help='rule id (0 = default policy)')
    ap.add_argument('--since', help='ISO time, e.g. 2026-11-11T18:00:00Z')
    ap.add_argument('--until')
    ap.add_argument('--threshold', type=int, default=5, help='alert if one source IP has this many denies')
    a = ap.parse_args()

    with open(a.path, 'r', encoding='utf-8') as f:
        events = [json.loads(x) for x in f if x.strip()]
    filtered = any([a.event, a.action, a.proto, a.src, a.dst_port, a.rule is not None, a.since, a.until])

    if filtered:
        found = [e for e in events if match(e, a)]
        for e in found:
            if e['event'].startswith('rule'):
                r = e.get('rule') or {}
                desc = (f"{r.get('action')} {r.get('proto')} {r.get('src_ip_cidr')}:{r.get('src_port') or '*'} -> "
                        f"{r.get('dst_ip_cidr')}:{r.get('dst_port') or '*'} prio {r.get('priority')}") if r else \
                       (json.dumps(e.get('changes')) if e.get('changes') else '')
                rid = e.get('rule_id') or r.get('id') or ''
                print(f"{e['ts']}  {e['event']:<14} {str(rid):<4} {desc} {' '.join(e.get('errors', []) + e.get('warnings', []))}")
                continue
            src = ':'.join(map(str, e['src'])) if e.get('src') else '-'
            dst = ':'.join(map(str, e['dst'])) if e.get('dst') else '-'
            print(f"{e['ts']}  {e['event']:<12} {e.get('action', ''):<6} {e.get('proto', ''):<4} "
                  f"{src:<22} -> {dst:<20} {e.get('reason') or e.get('rule_id', '')}")
        print(f'Found: {len(found)} of {len(events)}')
    else:
        by = collections.Counter(e['event'] for e in events)
        print('Events:', dict(by))
        denies = [e for e in events if e.get('action') == 'deny']
        print('Denied count:', len(denies))
        # групування за IP без порту: порт клієнта щоразу новий
        top_src = collections.Counter(e['src'][0] for e in denies).most_common(5)
        print('Top denied sources:', top_src)
        print('Denies by rule:', dict(collections.Counter(e.get('rule_id') for e in denies)))
        print('Denies by protocol:', dict(collections.Counter(e.get('proto') for e in denies)))
        print('Rule changes:')
        for e in events:
            if e['event'].startswith('rule'):
                rid = e.get('rule_id') or (e.get('rule') or {}).get('id') or ''
                print(f"  {e['ts']}  {e['event']:<14} {rid}")
        for ip, n in collections.Counter(e['src'][0] for e in denies).items():
            if n >= a.threshold:
                print(f'ALERT: {n} denied connections/packets from {ip}: possible scan or repeated access attempts')
