"""Демо-клієнт UDP: надсилає DNS-запит (A-запис) через UDP-сервіс брандмауера і виводить відповідь.
Запуск: python udp_client.py --name example.org --port 5353"""
import argparse, random, socket, struct

ap = argparse.ArgumentParser()
ap.add_argument('--host', default='127.0.0.1')
ap.add_argument('--port', type=int, default=5353)
ap.add_argument('--name', default='example.org')
a = ap.parse_args()

qid = random.randint(0, 0xFFFF)
query = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0)          # заголовок: рекурсивний запит, 1 питання
query += b''.join(bytes([len(p)]) + p.encode() for p in a.name.split('.')) + b'\x00'
query += struct.pack('>HH', 1, 1)                                 # тип A, клас IN

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(query, (a.host, a.port))
print(f'UDP: sent DNS query for {a.name} ({len(query)} bytes) to {a.host}:{a.port}')
try:
    resp, _ = s.recvfrom(4096)
except socket.timeout:
    print('UDP: no response within 3 s (packet blocked or target unreachable)')
    raise SystemExit(1)
ancount = struct.unpack('>H', resp[6:8])[0]


def skip_name(buf, i):
    while buf[i] != 0:
        if buf[i] & 0xC0 == 0xC0:      # стиснене ім'я (вказівник, 2 байти)
            return i + 2
        i += buf[i] + 1
    return i + 1


i = skip_name(resp, 12) + 4           # пропустити питання (ім'я + тип + клас)
ips = []
for _ in range(ancount):
    i = skip_name(resp, i)
    rtype, _, _, rdlen = struct.unpack('>HHIH', resp[i:i + 10])
    if rtype == 1 and rdlen == 4:
        ips.append(socket.inet_ntoa(resp[i + 10:i + 14]))
    i += 10 + rdlen
print(f'UDP: response {len(resp)} bytes, answers: {ancount}, A records: {ips}')
