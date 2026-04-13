from solution.rule_engine import RuleEngine
from solution.state_table import StateTable


class Firewall:
    def __init__(self, rule_engine):
        self.rule_engine = rule_engine
        self.state_table = StateTable()
        self.logged = []

    def process_packet(self, packet):
        # established connections bypass rule evaluation
        if self.state_table.is_established(packet):
            return "ALLOW"

        # stateless filtering: match packet against rules
        action = self.rule_engine.match(packet)

        # record the packet when the matched rule is LOG
        if action == "LOG":
            self.logged.append(packet)

        # TCP is tracked statefully
        if packet["protocol"] == "TCP":
            # detect anomalous behavior and log suspicious packets
            if self.state_table.is_anomalous(packet):
                if packet not in self.logged:
                    self.logged.append(packet)

            self.state_table.update(packet, action)

        return action