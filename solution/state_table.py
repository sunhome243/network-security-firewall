class StateTable:
    SYN_SENT = "SYN_SENT"
    ESTABLISHED = "ESTABLISHED"

    def __init__(self):
        self.connections = {}

    def _key(self, packet):
        return (
            packet["src_ip"],
            packet["src_port"],
            packet["dst_ip"],
            packet["dst_port"],
        )

    def is_established(self, packet):
        fwd = self._key(packet)
        rev = (packet["dst_ip"], packet["dst_port"], packet["src_ip"], packet["src_port"])
        return fwd in self.connections or rev in self.connections

    def is_anomalous(self, packet):
        flags = set(packet.get("flags", []))
        fwd = self._key(packet)
        rev = (packet["dst_ip"], packet["dst_port"], packet["src_ip"], packet["src_port"])

        # SYN-ACK with no prior SYN from the client
        if "SYN" in flags and "ACK" in flags:
            if self.connections.get(rev) != self.SYN_SENT:
                return True

        # ACK/RST/FIN with no known connection at all
        if flags & {"ACK", "RST", "FIN"} and "SYN" not in flags:
            if fwd not in self.connections and rev not in self.connections:
                return True

        return False

    def update(self, packet, action):
        flags = set(packet.get("flags", []))
        fwd = self._key(packet)
        rev = (packet["dst_ip"], packet["dst_port"], packet["src_ip"], packet["src_port"])

        if "SYN" in flags and "ACK" not in flags:
            self.connections[fwd] = self.SYN_SENT

        elif "SYN" in flags and "ACK" in flags:
            if self.connections.get(rev) == self.SYN_SENT:
                self.connections[rev] = self.ESTABLISHED

        elif "ACK" in flags:
            if self.connections.get(fwd) == self.SYN_SENT:
                self.connections[fwd] = self.ESTABLISHED