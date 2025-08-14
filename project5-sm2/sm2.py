import secrets
import binascii
from gmssl import sm3, func

C1 = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
C2 = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
C3 = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
C4 = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
C5 = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
C6 = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
G = (C5, C6)

def _x_op(x, y):
    if len(x) != len(y):
        return False
    r = 0
    for a, b in zip(x, y):
        r |= a ^ b
    return r == 0

def _y_op(v, m):
    if v == 0: return 0
    x, y, a, b = 1, 0, v % m, m
    while a > 1:
        q = b // a
        x, a, y, b = y - x * q, b - a * q, x, a
    return x % m

def _z_op(p1, p2):
    if p1 == (0, 0): return p2
    if p2 == (0, 0): return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        s = (3 * x1 * x1 + C1) * _y_op(2 * y1, C3)
    else:
        s = (y2 - y1) * _y_op(x2 - x1, C3)
    s %= C3
    x3 = (s * s - x1 - x2) % C3
    y3 = (s * (x1 - x3) - y1) % C3
    return (x3, y3)

def _a_op(k, p):
    if not 0 < k < C4:
        raise ValueError("error")
    r, cp = (0, 0), p
    while k:
        if k & 1: r = _z_op(r, cp)
        cp = _z_op(cp, cp)
        k >>= 1
    return r

class Processor:
    def __init__(self, key_data=None):
        if key_data:
            self.d_key = key_data[0]
            self.p_key = key_data[1]
        else:
            self.d_key, self.p_key = self._b_op()

    def _b_op(self):
        d_k = secrets.randbelow(C4 - 1) + 1
        p_k = _a_op(d_k, G)
        return d_k, p_k

    def _c_op(self, uid_str, p_x, p_y):
        uid_b = uid_str.encode('utf-8')
        l_uid = len(uid_b) * 8
        d_hash = b''.join([
            l_uid.to_bytes(2, 'big'), uid_b,
            C1.to_bytes(32, 'big'), C2.to_bytes(32, 'big'),
            C5.to_bytes(32, 'big'), C6.to_bytes(32, 'big'),
            p_x.to_bytes(32, 'big'), p_y.to_bytes(32, 'big')
        ])
        h_res = sm3.sm3_hash(func.bytes_to_list(d_hash))
        return bytes.fromhex(h_res)

    def process(self, msg_str, user_id):
        h = self._c_op(user_id, self.p_key[0], self.p_key[1])
        h_input = h + msg_str.encode('utf-8')
        e = int(sm3.sm3_hash(func.bytes_to_list(h_input)), 16)
        while True:
            k = secrets.randbelow(C4 - 1) + 1
            pk = _a_op(k, G)
            x_k = pk[0]
            r = (e + x_k) % C4
            if r == 0 or r + k == C4: continue
            s_inv = _y_op(1 + self.d_key, C4)
            s = (s_inv * (k - r * self.d_key)) % C4
            if s != 0:
                return (r, s)

    def verify(self, msg_str, user_id, sig):
        r, s = sig
        if not (0 < r < C4 and 0 < s < C4): return False
        h = self._c_op(user_id, self.p_key[0], self.p_key[1])
        h_input = h + msg_str.encode('utf-8')
        e = int(sm3.sm3_hash(func.bytes_to_list(h_input)), 16)
        t = (r + s) % C4
        ps = _a_op(s, G)
        pt = _a_op(t, self.p_key)
        res_p = _z_op(ps, pt)
        c_r = (e + res_p[0]) % C4
        return _x_op(r.to_bytes(32, 'big'), c_r.to_bytes(32, 'big'))

    def _d_op(self, z, klen):
        c, dk = 1, b''
        l_bytes = (klen + 7) // 8
        while len(dk) < l_bytes:
            in_data = z + c.to_bytes(4, 'big')
            h_out = bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(in_data)))
            dk += h_out
            c += 1
        return dk[:l_bytes]

    def secret_encode(self, data: bytes):
        if self.p_key == (0, 0): raise ValueError("error")
        k = secrets.randbelow(C4 - 1) + 1
        c1 = _a_op(k, G)
        x1, y1 = c1
        p_k = _a_op(k, self.p_key)
        x2, y2 = p_k
        xb, yb = x2.to_bytes(32, 'big'), y2.to_bytes(32, 'big')
        kdf_out = self._d_op(xb + yb, len(data) * 8)
        if all(b == 0 for b in kdf_out): raise ValueError("error")
        c2 = bytes(p ^ t for p, t in zip(data, kdf_out))
        c3_in = xb + data + yb
        c3 = bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(c3_in)))
        c1_bytes = x1.to_bytes(32, 'big') + y1.to_bytes(32, 'big')
        return c1_bytes + c3 + c2

    def secret_decode(self, c_text: bytes):
        if len(c_text) < 97: raise ValueError("error")
        c1_b = c_text[:64]
        c1_x = int.from_bytes(c1_b[:32], 'big')
        c1_y = int.from_bytes(c1_b[32:64], 'big')
        c1_p = (c1_x, c1_y)
        c3 = c_text[64:96]
        c2 = c_text[96:]
        p_k = _a_op(self.d_key, c1_p)
        x2, y2 = p_k
        xb, yb = x2.to_bytes(32, 'big'), y2.to_bytes(32, 'big')
        kdf_out = self._d_op(xb + yb, len(c2) * 8)
        if all(b == 0 for b in kdf_out): raise ValueError("error")
        d_text = bytes(c ^ k for c, k in zip(c2, kdf_out))
        c3_in = xb + d_text + yb
        c3_c = bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(c3_in)))
        if not _x_op(c3_c, c3): raise ValueError("error")
        return d_text

def run():
    p = Processor()
    print(p.d_key, p.p_key)

    msg = "hello"
    user_id = "user01"
    sig = p.process(msg, user_id)
    print(sig)
    print(p.verify(msg, user_id, sig))

    plain = b"this is a confidential message"
    cipher = p.secret_encode(plain)
    print(binascii.hexlify(cipher))
    decrypted = p.secret_decode(cipher)
    print(decrypted)

if __name__ == "__main__":
    run()
