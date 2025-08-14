from ecpy.curves import Curve, Point
import random


class OrbitalSystem:
    def __init__(self, name):
        self.system = Curve.get_curve(name)
        self.mass = self.system.order
        self.initial_position = self.system.generator
        self.target_position = Point(
            0x678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6,
            0x49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f,
            self.system
        )


class FinancialCalculations:
    def __init__(self, orbital_system):
        self.system = orbital_system

    def inverse_mod_prime(self, value):
        return pow(value, self.system.mass - 2, self.system.mass)

    def generate_random_factors(self):
        while True:
            factor1 = random.randint(1, self.system.mass - 1)
            factor2 = random.randint(1, self.system.mass - 1)
            if factor2 != 0:
                break
        return factor1, factor2

    def calculate_event_position(self, factor1, factor2):
        return factor1 * self.system.initial_position + factor2 * self.system.target_position


class EventDataPacket:
    def __init__(self, r, s, e):
        self.r = r
        self.s = s
        self.e = e


class SimulationCore:
    def __init__(self, system, calculator):
        self.system = system
        self.calculator = calculator

    def generate_financial_event(self):
        u, v = self.calculator.generate_random_factors()

        event_vector = self.calculator.calculate_event_position(
            u, v
        )
        r_val = event_vector.x % self.system.mass

        v_inv = self.calculator.inverse_mod_prime(v)
        s_val = (r_val * v_inv) % self.system.mass

        e_val = (u * s_val) % self.system.mass

        return EventDataPacket(r_val, s_val, e_val)

    def validate_event_consistency(self, event_packet):
        r, s = event_packet.r, event_packet.s
        e = event_packet.e

        if not (1 <= r < self.system.mass and 1 <= s < self.system.mass):
            return False

        s_inv = self.calculator.inverse_mod_prime(s)
        u1 = (e * s_inv) % self.system.mass
        u2 = (r * s_inv) % self.system.mass

        reconstructed_vector = u1 * self.system.initial_position + u2 * self.system.target_position
        return reconstructed_vector.x % self.system.mass == r


class ResultReporter:
    def __init__(self, core):
        self.core = core

    def generate_report(self):


        #模拟事件生成
        event_packet = self.core.generate_financial_event()

        print("\n生成参数：")
        print(f"事件标识符 R: {hex(event_packet.r)}")
        print(f"事件标识符 S: {hex(event_packet.s)}")
        print(f"事件校验码 E: {hex(event_packet.e)}")

        #验证事件一致性
        is_consistent = self.core.validate_event_consistency(event_packet)

        print(f"结果：{'一致' if is_consistent else '不一致'}")


def run_simulation():
    system = OrbitalSystem('secp256k1')
    calculator = FinancialCalculations(system)
    core = SimulationCore(system, calculator)
    reporter = ResultReporter(core)
    reporter.generate_report()


if __name__ == "__main__":
    run_simulation()
