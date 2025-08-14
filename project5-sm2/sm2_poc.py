import secrets
import binascii
from hashlib import sha256
from gmssl import sm3, func
import time
import functools

#参数表
_CONFIG = {
    'p1': 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498,
    'p2': 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A,
    'mod': 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3,
    'order': 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7,
    'bx': 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D,
    'by': 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2,
    'point_g': (0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D,
                0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2),
}

_CACHE_A = {}
_CACHE_B = {}


def _core_op(v, m):
    if (v, m) in _CACHE_A: return _CACHE_A[(v, m)]
    if v == 0: return 0
    l, h, low, high = 1, 0, v % m, m
    while low > 1:
        r = high // low
        l, low, h, high = h - l * r, high - low * r, l, low
    res = l % m
    _CACHE_A[(v, m)] = res
    return res


def _vector_add(p1, p2):
    if (p1, p2) in _CACHE_B: return _CACHE_B[(p1, p2)]
    if p1 == (0, 0): return p2
    if p2 == (0, 0): return p1
    x1, y1 = p1
    x2, y2 = p2
    mod = _CONFIG['mod']
    if x1 == x2:
        if y1 == y2:
            s = (3 * x1 * x1 + _CONFIG['p1']) * _core_op(2 * y1, mod)
        else:
            return (0, 0)
    else:
        s = (y2 - y1) * _core_op(x2 - x1, mod)
    s %= mod
    x3 = (s * s - x1 - x2) % mod
    y3 = (s * (x1 - x3) - y1) % mod
    res = (x3, y3)
    _CACHE_B[(p1, p2)] = res
    return res


def _vector_scale(s, p):
    res, cur = (0, 0), p
    while s:
        if s & 1: res = _vector_add(res, cur)
        cur = _vector_add(cur, cur)
        s >>= 1
    return res


def _calc_h(uid, px, py):
    l = len(uid.encode('utf-8')) * 8
    comps = [
        l.to_bytes(2, 'big'), uid.encode('utf-8'),
        _CONFIG['p1'].to_bytes(32, 'big'), _CONFIG['p2'].to_bytes(32, 'big'),
        _CONFIG['bx'].to_bytes(32, 'big'), _CONFIG['by'].to_bytes(32, 'big'),
        px.to_bytes(32, 'big'), py.to_bytes(32, 'big')
    ]
    data = b''.join(comps)
    return bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(data)))


def _get_params():
    d = secrets.randbelow(_CONFIG['order'] - 1) + 1
    p = _vector_scale(d, _CONFIG['point_g'])
    return {'d': d, 'p': p}


class DataProcessor:
    def __init__(self):
        pass

    def process_sm2_data(self, data):
        d, p = data['d'], data['p']
        msg, uid, k = data['msg'], data['uid'], data.get('k')

        h_val = _calc_h(uid, p[0], p[1])
        e = int(sm3.sm3_hash(func.bytes_to_list(h_val + msg.encode('utf-8'))), 16)

        k_val = k if k else secrets.randbelow(_CONFIG['order'] - 1) + 1
        x_k = _vector_scale(k_val, _CONFIG['point_g'])[0]
        r = (e + x_k) % _CONFIG['order']
        if r == 0 or r + k_val == _CONFIG['order']: return None

        s = (_core_op(1 + d, _CONFIG['order']) * (k_val - r * d)) % _CONFIG['order']
        return {'r': r, 's': s, 'k': k_val, 'e': e}

    def process_ecdsa_data(self, data):
        d, msg, k = data['d'], data['msg'], data.get('k')

        e = int.from_bytes(sha256(msg.encode('utf-8')).digest(), 'big') % _CONFIG['order']

        k_val = k if k else secrets.randbelow(_CONFIG['order'] - 1) + 1
        r = _vector_scale(k_val, _CONFIG['point_g'])[0] % _CONFIG['order']
        if r == 0: return None

        s = _core_op(k_val, _CONFIG['order']) * (e + d * r) % _CONFIG['order']
        if s == 0: return None
        return {'r': r, 's': s, 'k': k_val, 'e': e}

    def verify_proc_a(self):
        params = _get_params()
        d_key, p_key = params['d'], params['p']
        k_val = secrets.randbelow(_CONFIG['order'] - 1) + 1
        data = {'d': d_key, 'p': p_key, 'msg': "test_msg", 'uid': "user1", 'k': k_val}
        sig = self.process_sm2_data(data)

        denom = (sig['s'] + sig['r']) % _CONFIG['order']
        rec_d = ((sig['k'] - sig['s']) * _core_op(denom, _CONFIG['order'])) % _CONFIG['order']
        return d_key, rec_d

    def verify_proc_b(self):
        params = _get_params()
        d_key, p_key = params['d'], params['p']
        k_val = secrets.randbelow(_CONFIG['order'] - 1) + 1
        data_a = {'d': d_key, 'p': p_key, 'msg': "msg_a", 'uid': "user", 'k': k_val}
        data_b = {'d': d_key, 'p': p_key, 'msg': "msg_b", 'uid': "user", 'k': k_val}
        sig_a = self.process_sm2_data(data_a)
        sig_b = self.process_sm2_data(data_b)

        num = (sig_b['s'] - sig_a['s']) % _CONFIG['order']
        den = (sig_a['s'] - sig_b['s'] + sig_a['r'] - sig_b['r']) % _CONFIG['order']
        rec_d = (num * _core_op(den, _CONFIG['order'])) % _CONFIG['order']
        return d_key, rec_d

    def verify_proc_c(self):
        params_a = _get_params()
        params_b = _get_params()
        k_val = secrets.randbelow(_CONFIG['order'] - 1) + 1
        data_a = {'d': params_a['d'], 'p': params_a['p'], 'msg': "msg_a", 'uid': "user_a", 'k': k_val}
        data_b = {'d': params_b['d'], 'p': params_b['p'], 'msg': "msg_b", 'uid': "user_b", 'k': k_val}
        sig_a = self.process_sm2_data(data_a)
        sig_b = self.process_sm2_data(data_b)

        k_rec = (sig_a['s'] * (1 + params_a['d']) + sig_a['r'] * params_a['d']) % _CONFIG['order']
        den = (sig_b['s'] + sig_b['r']) % _CONFIG['order']
        rec_d = ((k_rec - sig_b['s']) * _core_op(den, _CONFIG['order'])) % _CONFIG['order']
        return params_b['d'], rec_d

    def verify_proc_d(self):
        params = _get_params()
        d_key, p_key = params['d'], params['p']
        k_val = secrets.randbelow(_CONFIG['order'] - 1) + 1
        data_ecdsa = {'d': d_key, 'msg': "ecdsa_msg", 'k': k_val}
        data_sm2 = {'d': d_key, 'p': p_key, 'msg': "sm2_msg", 'uid': "user", 'k': k_val}
        sig_ecdsa = self.process_ecdsa_data(data_ecdsa)
        sig_sm2 = self.process_sm2_data(data_sm2)

        e1 = sig_ecdsa['e']
        r1, s1 = sig_ecdsa['r'], sig_ecdsa['s']
        r2, s2 = sig_sm2['r'], sig_sm2['s']

        num = (s1 * s2 - e1) % _CONFIG['order']
        den = (r1 - s1 * s2 - s1 * r2) % _CONFIG['order']
        rec_d = (num * _core_op(den, _CONFIG['order'])) % _CONFIG['order']
        return d_key, rec_d


def main():
    processor = DataProcessor()

    print("Test Group A")
    orig_a, rec_a = processor.verify_proc_a()
    print(f"  Input: {hex(orig_a)}")
    print(f"  Output: {hex(rec_a)}")
    print(f"  Result: {orig_a == rec_a}\n")

    print("Test Group B")
    orig_b, rec_b = processor.verify_proc_b()
    print(f"  Input: {hex(orig_b)}")
    print(f"  Output: {hex(rec_b)}")
    print(f"  Result: {orig_b == rec_b}\n")

    print("Test Group C")
    orig_c, rec_c = processor.verify_proc_c()
    print(f"  Input: {hex(orig_c)}")
    print(f"  Output: {hex(rec_c)}")
    print(f"  Result: {orig_c == rec_c}\n")

    print("Test Group D")
    orig_d, rec_d = processor.verify_proc_d()
    print(f"  Input: {hex(orig_d)}")
    print(f"  Output: {hex(rec_d)}")
    print(f"  Result: {orig_d == rec_d}\n")


if __name__ == "__main__":
    main()
