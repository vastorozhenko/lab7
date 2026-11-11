import argparse, json, os, threading, time, socket, selectors, ipaddress
from http.server import BaseHTTPRequestHandler, HTTPServer
from dataclasses import dataclass, field, asdict
from typing import List

LOG_PATH = 'logs/events.jsonl'
LOG_LOCK = threading.Lock()


def jlog(obj):
    """Один JSON-запис на рядок. Час у UTC (ISO 8601), щоб зручно шукати й сортувати."""
    rec = {'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    rec.update(obj)
    with LOG_LOCK:
        os.makedirs(os.path.dirname(LOG_PATH) or '.', exist_ok=True)
        with open(LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')


@dataclass
class Rule:
    priority: int
    id: int = 0
    action: str = 'deny'          # 'allow' | 'deny'
    src_ip_cidr: str = '0.0.0.0/0'
    dst_ip_cidr: str = '0.0.0.0/0'
    src_port: int = 0             # 0 = any
    dst_port: int = 0
    proto: str = 'TCP'            # 'TCP' | 'UDP'
    enabled: bool = True

    def matches(self, src_ip, dst_ip, src_port, dst_port, proto):
        if not self.enabled: return False
        if self.proto != proto.upper(): return False
        if ipaddress.ip_address(src_ip) not in ipaddress.ip_network(self.src_ip_cidr): return False
        if ipaddress.ip_address(dst_ip) not in ipaddress.ip_network(self.dst_ip_cidr): return False
        if self.src_port and self.src_port != src_port: return False
        if self.dst_port and self.dst_port != dst_port: return False
        return True

    def describe(self):
        return (f"rule {self.id} (prio {self.priority}): {self.action} {self.proto} "
                f"{self.src_ip_cidr}:{self.src_port or '*'} -> {self.dst_ip_cidr}:{self.dst_port or '*'}")


FIELDS = {'priority', 'action', 'src_ip_cidr', 'dst_ip_cidr', 'src_port', 'dst_port', 'proto', 'enabled'}


def make_rule(d: dict, rid: int = 0) -> Rule:
    """Перевірка й нормалізація полів правила. Некоректне правило відхиляється з поясненням."""
    unknown = set(d) - FIELDS - {'id'}
    if unknown:
        raise ValueError(f'unknown fields: {sorted(unknown)}')
    action = str(d.get('action', 'deny')).lower()
    if action not in ('allow', 'deny'):
        raise ValueError('action must be allow or deny')
    proto = str(d.get('proto', 'TCP')).upper()
    if proto not in ('TCP', 'UDP'):
        raise ValueError('proto must be TCP or UDP')
    cidrs = {}
    for k in ('src_ip_cidr', 'dst_ip_cidr'):
        try:
            cidrs[k] = str(ipaddress.ip_network(str(d.get(k, '0.0.0.0/0')), strict=False))
        except ValueError:
            raise ValueError(f'{k} is not a valid IP/CIDR: {d.get(k)}')
    ports = {}
    for k in ('src_port', 'dst_port'):
        v = d.get(k, 0)
        if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= 65535:
            raise ValueError(f'{k} must be an integer 0..65535 (0 = any)')
        ports[k] = v
    prio = d.get('priority', 100)
    if isinstance(prio, bool) or not isinstance(prio, int) or prio < 0:
        raise ValueError('priority must be a non-negative integer')
    enabled = d.get('enabled', True)
    if not isinstance(enabled, bool):
        raise ValueError('enabled must be true or false')
    return Rule(priority=prio, id=rid, action=action, proto=proto, enabled=enabled, **cidrs, **ports)


# ---------- Виявлення конфліктів ----------

def _ports_overlap(a, b): return a == 0 or b == 0 or a == b
def _port_covers(a, b): return a == 0 or a == b            # a містить b
def _net(c): return ipaddress.ip_network(c)


def _same_match(a: Rule, b: Rule):
    return (a.proto, a.src_ip_cidr, a.dst_ip_cidr, a.src_port, a.dst_port) == \
           (b.proto, b.src_ip_cidr, b.dst_ip_cidr, b.src_port, b.dst_port)


def _overlap(a: Rule, b: Rule):
    """Чи існує пакет, який підпадає під обидва правила."""
    return (a.proto == b.proto and _net(a.src_ip_cidr).overlaps(_net(b.src_ip_cidr))
            and _net(a.dst_ip_cidr).overlaps(_net(b.dst_ip_cidr))
            and _ports_overlap(a.src_port, b.src_port) and _ports_overlap(a.dst_port, b.dst_port))


def _covers(a: Rule, b: Rule):
    """Чи кожен пакет правила b підпадає також під правило a."""
    return (a.proto == b.proto and _net(b.src_ip_cidr).subnet_of(_net(a.src_ip_cidr))
            and _net(b.dst_ip_cidr).subnet_of(_net(a.dst_ip_cidr))
            and _port_covers(a.src_port, b.src_port) and _port_covers(a.dst_port, b.dst_port))


def _first(a: Rule, b: Rule):
    """Яке з двох правил перевіряється раніше: менший priority, при рівності менший id."""
    return a if (a.priority, a.id) < (b.priority, b.id) else b


def check_conflicts(new: Rule, others: List[Rule]):
    """Повертає (errors, warnings) у вигляді рядків.
    errors   -> правило не приймається (дублікат або неоднозначний конфлікт);
    warnings -> правило приймається, але користувач бачить, яке правило переможе або що воно не спрацює."""
    errors, warnings = [], []
    for x in others:
        if _same_match(x, new) and x.action == new.action:
            errors.append(f'duplicate of rule {x.id}: same match fields and action')
            continue
        if _same_match(x, new) and x.priority == new.priority:
            errors.append(f'conflict with rule {x.id}: same match fields and priority, different action')
            continue
        if not (x.enabled and new.enabled):    # перекриття аналізуються лише між увімкненими правилами
            continue
        if _covers(x, new) and _first(x, new) is x:
            warnings.append(f'shadowed by rule {x.id} ({x.action}, priority {x.priority}): '
                            f'this rule will never apply')
        elif _overlap(x, new) and x.action != new.action:
            w = _first(x, new)
            warnings.append(f'overlap with rule {x.id} ({x.action}): for common traffic '
                            f'rule {w.id} ({w.action}, priority {w.priority}) wins')
    return errors, warnings


class RuleSet:
    """Таблиця правил. Змінюється на місці під замком, тому проксі одразу бачать зміни."""
    def __init__(self, rules=None):
        self.lock = threading.Lock()
        self.rules: List[Rule] = []
        self.replace(rules or [])

    def replace(self, rules):
        with self.lock:
            self.rules[:] = sorted(rules, key=lambda r: (r.priority, r.id))
            self.next_id = max((r.id for r in self.rules), default=0) + 1

    def to_dict(self):
        with self.lock:
            return [asdict(r) for r in self.rules]

    def add(self, r: Rule):
        with self.lock:
            r.id = self.next_id                 # id потрібен уже під час перевірки (порядок при рівному priority)
            errors, warnings = check_conflicts(r, self.rules)
            if errors:
                return None, errors, warnings
            self.next_id += 1
            self.rules.append(r); self.rules.sort(key=lambda x: (x.priority, x.id))
            return r, [], warnings

    def remove(self, rid: int):
        with self.lock:
            before = len(self.rules)
            self.rules[:] = [r for r in self.rules if r.id != rid]
            return len(self.rules) < before

    def update(self, rid: int, changes: dict):
        with self.lock:
            cur = next((r for r in self.rules if r.id == rid), None)
            if cur is None:
                return None, ['not_found'], []
            new = make_rule({**{k: v for k, v in asdict(cur).items() if k != 'id'}, **changes}, rid)
            errors, warnings = check_conflicts(new, [r for r in self.rules if r.id != rid])
            if errors:
                return None, errors, warnings
            self.rules[self.rules.index(cur)] = new
            self.rules.sort(key=lambda x: (x.priority, x.id))
            return new, [], warnings

    def audit(self):
        """Перевірка всієї таблиці на конфлікти (наприклад, після ручного редагування config.json і reload)."""
        with self.lock:
            rules = list(self.rules)
        report = []
        for i, r in enumerate(rules):
            errors, warnings = check_conflicts(r, rules[:i])
            for msg in errors + warnings:
                report.append(f'rule {r.id}: {msg}')
        return report

    def decide(self, src_ip, dst_ip, src_port, dst_port, proto):
        with self.lock:
            for r in self.rules:
                if r.matches(src_ip, dst_ip, src_port, dst_port, proto):
                    return r.action, r.id, r.describe()
        return 'allow', 0, 'no matching rule: default allow'


def log_decision(event, proto, addr, dst, action, rid, reason, **extra):
    jlog({'event': event, 'action': action, 'proto': proto, 'src': list(addr), 'dst': list(dst),
          'rule_id': rid, 'reason': reason, **extra})


# TCP proxy
def tcp_proxy(listen_host, listen_port, target_host, target_port, ruleset: RuleSet):
    sel = selectors.DefaultSelector()
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((listen_host, listen_port)); ls.listen(128); ls.setblocking(False)
    sel.register(ls, selectors.EVENT_READ)

    def accept(sock):
        conn, addr = sock.accept(); conn.setblocking(False)
        src_ip, src_port = addr[0], addr[1]
        dst_ip = socket.gethostbyname(target_host); dst_port = target_port
        action, rid, reason = ruleset.decide(src_ip, dst_ip, src_port, dst_port, 'TCP')
        log_decision('tcp.connect', 'TCP', addr, (dst_ip, dst_port), action, rid, reason)
        if action != 'allow':
            conn.close(); return
        try:
            upstream = socket.create_connection((target_host, target_port), timeout=5)
            upstream.setblocking(False)
        except Exception as e:
            jlog({'event': 'tcp.error', 'proto': 'TCP', 'src': list(addr), 'dst': [target_host, target_port], 'err': str(e)})
            conn.close(); return
        sel.register(conn, selectors.EVENT_READ, data=('c', upstream))
        sel.register(upstream, selectors.EVENT_READ, data=('u', conn))

    def forward(src, dst, tag):
        try:
            data = src.recv(4096)
            if not data:
                sel.unregister(src); sel.unregister(dst); src.close(); dst.close(); return
            dst.sendall(data)
        except Exception:
            try:
                sel.unregister(src); sel.unregister(dst)
            except Exception: pass
            src.close(); dst.close()

    while True:
        for key, mask in sel.select(timeout=1):
            if key.fileobj is ls:
                accept(ls)
            else:
                role, peer = key.data
                forward(key.fileobj, peer, role)


# UDP relay
def udp_proxy(listen_host, listen_port, target_host, target_port, ruleset: RuleSet):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((listen_host, listen_port))
    while True:
        data, addr = sock.recvfrom(65535)
        src_ip, src_port = addr
        dst_ip = socket.gethostbyname(target_host); dst_port = target_port
        action, rid, reason = ruleset.decide(src_ip, dst_ip, src_port, dst_port, 'UDP')
        log_decision('udp.packet', 'UDP', addr, (dst_ip, dst_port), action, rid, reason, bytes=len(data))
        if action != 'allow': continue
        # send to target and relay back response (best-effort)
        try:
            upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstream.settimeout(2)
            upstream.sendto(data, (dst_ip, dst_port))
            try:
                resp, _ = upstream.recvfrom(65535)
                sock.sendto(resp, addr)
            except socket.timeout:
                pass
            upstream.close()
        except Exception as e:
            jlog({'event': 'udp.error', 'proto': 'UDP', 'src': list(addr), 'err': str(e)})


# Admin API (stdlib http.server)
class Admin(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):     # не засмічувати консоль HTTP-логами
        pass

    def _json(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode()
        self.send_response(code); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body))); self.end_headers()
        self.wfile.write(body)

    def _body(self):
        ln = int(self.headers.get('Content-Length', '0'))
        return json.loads(self.rfile.read(ln) or b'{}')

    def _rid(self):
        return int(self.path.rstrip('/').split('/')[-1])

    def do_GET(self):
        if self.path.rstrip('/') == '/rules':
            self._json(200, rules.ruleset.to_dict())
        elif self.path.rstrip('/') == '/conflicts':
            self._json(200, rules.ruleset.audit())
        else:
            self._json(404, {'error': 'not_found'})

    def do_POST(self):
        if self.path.rstrip('/') == '/rules':
            try:
                r = make_rule(self._body())
            except (ValueError, json.JSONDecodeError) as e:
                return self._json(400, {'error': 'bad_rule', 'detail': str(e)})
            added, errors, warnings = rules.ruleset.add(r)
            if errors:
                jlog({'event': 'rule.rejected', 'rule': {k: v for k, v in asdict(r).items() if k != 'id'}, 'errors': errors})
                return self._json(409, {'error': 'rule_rejected', 'errors': errors})
            rules.save()
            jlog({'event': 'rule.add', 'rule': asdict(added), 'warnings': warnings})
            self._json(201, {'id': added.id, 'warnings': warnings})
        elif self.path.rstrip('/') == '/reload':
            try:
                rules.load()
            except (ValueError, OSError, json.JSONDecodeError) as e:
                return self._json(400, {'error': 'reload_failed', 'detail': str(e)})
            jlog({'event': 'rules.reload', 'count': len(rules.ruleset.rules)})
            self._json(200, {'ok': True, 'rules': len(rules.ruleset.rules), 'conflicts': rules.ruleset.audit()})
        else:
            self._json(404, {'error': 'not_found'})

    def do_PATCH(self):
        if not self.path.startswith('/rules/'):
            return self._json(404, {'error': 'not_found'})
        try:
            rid, changes = self._rid(), self._body()
            if 'id' in changes:
                raise ValueError('id cannot be changed')
            new, errors, warnings = rules.ruleset.update(rid, changes)
        except (ValueError, json.JSONDecodeError) as e:
            return self._json(400, {'error': 'bad_rule', 'detail': str(e)})
        if errors:
            code = 404 if errors[0] == 'not_found' else 409
            return self._json(code, {'error': 'update_rejected', 'errors': errors})
        rules.save()
        jlog({'event': 'rule.update', 'rule_id': rid, 'changes': changes, 'warnings': warnings})
        self._json(200, {'ok': True, 'rule': asdict(new), 'warnings': warnings})

    def do_DELETE(self):
        if not self.path.startswith('/rules/'):
            return self._json(404, {'error': 'not_found'})
        try:
            rid = self._rid()
        except ValueError:
            return self._json(400, {'error': 'bad_id'})
        if not rules.ruleset.remove(rid):
            return self._json(404, {'ok': False, 'error': 'not_found'})
        rules.save()
        jlog({'event': 'rule.delete', 'rule_id': rid})
        self._json(200, {'ok': True})


class RuleManager:
    """Читає config.json і зберігає в нього зміни правил, щоб вони не губилися після reload чи перезапуску."""
    def __init__(self, path):
        self.path = path
        self.ruleset = RuleSet([])
        self.load()

    def load(self):
        with open(self.path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
        global LOG_PATH
        LOG_PATH = cfg.get('logging', {}).get('path', LOG_PATH)
        base_rules = [make_rule(r, r.get('id', 0)) for r in cfg.get('rules', [])]
        ids = [r.id for r in base_rules]
        if 0 in ids or len(set(ids)) != len(ids):       # правила без id або з однаковим id отримують нові id
            for i, r in enumerate(base_rules, 1):
                r.id = i
        self.ruleset.replace(base_rules)               # заміна на місці: проксі бачать нові правила одразу
        self.services = cfg.get('services', [])
        self.admin = cfg.get('admin', {})

    def save(self):
        with open(self.path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
        cfg['rules'] = self.ruleset.to_dict()
        tmp = self.path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--config', default='config.json')
    args = ap.parse_args()
    global rules
    rules = RuleManager(args.config)

    # Start admin API
    host, port = rules.admin.get('host', '127.0.0.1'), rules.admin.get('port', 8081)
    admin = HTTPServer((host, port), Admin)
    threading.Thread(target=admin.serve_forever, daemon=True).start()

    # Start services
    threads = []
    for s in rules.services:
        if s.get('proto') == 'TCP':
            t = threading.Thread(target=tcp_proxy, args=(s['listen_host'], s['listen_port'], s['target_host'], s['target_port'], rules.ruleset), daemon=True)
        else:
            t = threading.Thread(target=udp_proxy, args=(s['listen_host'], s['listen_port'], s['target_host'], s['target_port'], rules.ruleset), daemon=True)
        t.start(); threads.append(t)

    print(f'Admin API http://{host}:{port}  |  Rules: {len(rules.ruleset.rules)}  |  Services:')
    for s in rules.services:
        print(f"  {s['proto']} {s['listen_host']}:{s['listen_port']} -> {s['target_host']}:{s['target_port']}")
    [t.join() for t in threads]


if __name__ == '__main__':
    main()
