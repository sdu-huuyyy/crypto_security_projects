import random
import hashlib
from typing import List, Tuple, Dict
from math import gcd

class CryptoCore:
    
    @staticmethod
    def is_likely_prime(n: int, rounds: int = 128) -> bool:
        """Miller-Rabin素性检测"""
        if n in (2, 3): return True
        if n < 2 or n % 2 == 0: return False
        
        # 分解n-1为d*2^s
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1
            
        # 进行多轮测试
        for _ in range(rounds):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    
    @staticmethod
    def generate_random_prime(size: int) -> int:
        """生成指定位数的随机素数"""
        while True:
            candidate = random.getrandbits(size) | 1  # 确保是奇数
            if CryptoCore.is_likely_prime(candidate):
                return candidate
    
    @staticmethod
    def modular_inverse(a: int, m: int) -> int:
        """计算模逆元"""
        return pow(a, -1, m)

class HiddenDataEngine:
    """基于Paillier的同态加密引擎"""
    
    def __init__(self, bit_length: int = 1024):
        # 生成两个大素数
        p1 = CryptoCore.generate_random_prime(bit_length // 2)
        p2 = CryptoCore.generate_random_prime(bit_length // 2)
        
        self._N = p1 * p2  # 模数
        self._N_squared = self._N * self._N
        self._G = self._N + 1  # 固定生成元
        
        # 计算私钥参数
        _lambda = (p1 - 1) * (p2 - 1) // gcd(p1 - 1, p2 - 1)
        self._mu_secret = CryptoCore.modular_inverse(_lambda, self._N)
        
        self.key_public = self._N  # 公钥
        self._key_private = (_lambda, self._mu_secret)  # 私钥
    
    def conceal(self, data: int) -> int:
        """加密数据"""
        rand_param = random.randint(1, self._N - 1)
        while gcd(rand_param, self._N) != 1:
            rand_param = random.randint(1, self._N - 1)
        return (pow(self._G, data, self._N_squared) * pow(rand_param, self._N, self._N_squared)) % self._N_squared
    
    def unseal(self, encrypted_data: int) -> int:
        """解密数据"""
        _lambda, _mu = self._key_private
        val = pow(encrypted_data, _lambda, self._N_squared)
        l_func_val = (val - 1) // self._N
        return (l_func_val * _mu) % self._N
    
    @staticmethod
    def combine(c1: int, c2: int, mod_squared: int) -> int:
        """同态加法：加密数据相加"""
        return (c1 * c2) % mod_squared

class DiffieHellmanGroup:
    """Diffie-Hellman密钥交换组"""
    
    def __init__(self, key_length: int = 512):
        # 生成安全素数p和子群阶q
        while True:
            prime_q = CryptoCore.generate_random_prime(key_length)
            prime_p = 2 * prime_q + 1  # 确保p是安全素数
            if CryptoCore.is_likely_prime(prime_p):
                self._p = prime_p
                self._q = prime_q
                self._g = random.randint(2, prime_p - 2)  # 生成元
                if pow(self._g, self._q, self._p) == 1:  # 验证生成元有效性
                    break
    
    def get_context(self) -> Tuple[int, int, int]:
        """获取DH参数(p, q, g)"""
        return self._p, self._q, self._g
    
    def process_element(self, element: str, power: int) -> int:
        """处理元素：H(element)^power mod p"""
        hashed_val = int(hashlib.sha256(element.encode()).hexdigest(), 16)
        return pow(pow(self._g, hashed_val % self._q, self._p), power, self._p)

def collaborative_computation(data_provider_1: List[str], data_provider_2: List[Tuple[str, int]]):
    """安全多方计算协议"""
    
    print("--- 系统初始化阶段 ---")
    shared_group = DiffieHellmanGroup()
    P, Q, G = shared_group.get_context()
    
    # 各方生成秘密参数
    secret_A = random.randint(1, Q - 1)  # 方1的秘密指数
    secret_B = random.randint(1, Q - 1)  # 方2的秘密指数
    secret_system = HiddenDataEngine()  # 同态加密系统
    public_param_N = secret_system.key_public
    print("初始化完毕。各方已拥有秘密参数。\n")
    
    print("--- 阶段一：数据封装 ---")
    # 方1处理自己的数据集
    encrypted_set_A = [shared_group.process_element(item, secret_A) for item in data_provider_1]
    random.shuffle(encrypted_set_A)  # 随机打乱顺序
    print("方1已处理其集合。")
    
    print("--- 阶段二：交叉处理 ---")
    # 方2处理方1的数据
    cross_processed_A = [pow(val, secret_B, P) for val in encrypted_set_A]
    shuffled_cross_A = cross_processed_A.copy()
    random.shuffle(shuffled_cross_A)
    
    # 方2处理自己的数据集
    processed_set_B = []
    for item, value in data_provider_2:
        _processed_item = shared_group.process_element(item, secret_B)
        _concealed_value = secret_system.conceal(value)  # 加密数值
        processed_set_B.append((_processed_item, _concealed_value))
    random.shuffle(processed_set_B)
    print("方2已完成对两组数据的交叉处理和封装。")
    
    print("--- 阶段三：数据匹配与汇总 ---")
    # 方1处理方2的数据
    final_processed_B = [(pow(h_val, secret_A, P), e_val) for h_val, e_val in processed_set_B]
    
    # 匹配相同项并累加加密值
    matches_found = 0
    final_sum_payloads = []
    map_B = {h_val: e_val for h_val, e_val in final_processed_B}
    
    for val in shuffled_cross_A:
        if val in map_B:
            matches_found += 1
            final_sum_payloads.append(map_B[val])
    
    # 同态累加所有匹配项的加密值
    if not final_sum_payloads:
        final_encrypted_sum = secret_system.conceal(0)
    else:
        final_encrypted_sum = final_sum_payloads[0]
        for i in range(1, len(final_sum_payloads)):
            final_encrypted_sum = HiddenDataEngine.combine(final_encrypted_sum, final_sum_payloads[i], secret_system._N_squared)
    
    print("方1已完成匹配和数据累加。")
    
    print("\n--- 结果揭示阶段 ---")
    final_output = secret_system.unseal(final_encrypted_sum)  # 解密最终结果
    print("最终结果已由方2解密。")
    print(f"匹配项数量: {matches_found}")
    print(f"匹配项关联值总和: {final_output}")
    return matches_found, final_output

if __name__ == "__main__":
    # 测试数据
    alpha_data = ["userA", "userB", "userC", "userD"]
    beta_data = [
        ("userA", 100),
        ("userC", 200),
        ("userE", 50),
        ("userF", 75)
    ]
    
    # 执行安全计算
    match_count, total_value = collaborative_computation(alpha_data, beta_data)
    
    print("\n--- 最终核对 ---")
    print(f"预期匹配数量: 2")
    print(f"预期总和: 300")
    assert match_count == 2
    assert total_value == 300
    print("核对成功！")
