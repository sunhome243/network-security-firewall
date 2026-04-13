class StateTable:
    def __init__(self):
        self.connections = set()

    def _key(self, packet):
        return (
            packet["src_ip"],
            packet["src_port"],
            packet["dst_ip"],
            packet["dst_port"],
        )

    def is_established(self, packet):
        fwd = self._key(packet)
        # reverse key to recognize reply traffic (e.g. SYN-ACK, server responses)
        rev = (packet["dst_ip"], packet["dst_port"], packet["src_ip"], packet["src_port"])
        return fwd in self.connections or rev in self.connections

    def update(self, packet, action):
        # store regardless of action so subsequent packets in the same flow. bypass rule evaluation via is_established
        self.connections.add(self._key(packet))
