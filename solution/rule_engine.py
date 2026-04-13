class Rule:
    """Represent a single packet-filtering rule."""

    def __init__(self, action, protocol, src, dst, dport):
        """Store the action and packet fields used for matching."""
        self.action = action
        self.protocol = protocol
        self.src = src
        self.dst = dst
        self.dport = dport

    def matches(self, packet):
        """Return True when the packet satisfies every rule constraint."""
        import ipaddress

        # "ALL" matches any protocol (e.g LOG ALL); otherwise must match exactly
        if self.protocol != "ALL" and self.protocol != packet["protocol"]:
            return False
        # "ANY" skips the check; otherwise match against CIDR range (e.g 10.0.0.0/24)
        if self.src != "ANY":
            if ipaddress.ip_address(packet["src_ip"]) not in ipaddress.ip_network(self.src, strict=False):
                return False
        if self.dst != "ANY":
            if ipaddress.ip_address(packet["dst_ip"]) not in ipaddress.ip_network(self.dst, strict=False):
                return False
        # "ANY" skips the check; otherwise must match exactly
        if self.dport != "ANY" and self.dport != packet["dst_port"]:
            return False
        return True


class RuleEngine:
    """Apply ordered firewall rules using first-match semantics."""

    def __init__(self, rules):
        """Store the rule list in evaluation order."""
        self.rules = rules

    def match(self, packet):
        """Return the action for the first matching rule or the default drop."""
        # evaluate rules top-down; return the first match (first-match policy)
        for rule in self.rules:
            if rule.matches(packet):
                return rule.action
        # no rule matched. default policy is DROP
        return "DROP"
