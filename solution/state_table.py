class StateTable:
    """Track TCP connection state for simple stateful firewall decisions."""

    SYN_SENT = "SYN_SENT"
    ESTABLISHED = "ESTABLISHED"

    def __init__(self):
        """Initialize the in-memory connection table."""
        self.connections = {}

    def _key(self, packet):
        """Return the canonical 4-tuple for a packet direction."""
        return (
            packet["src_ip"],
            packet["src_port"],
            packet["dst_ip"],
            packet["dst_port"],
        )

    def is_established(self, packet):
        """Check whether either direction of the flow is already known."""
        fwd = self._key(packet)
        rev = (packet["dst_ip"], packet["dst_port"], packet["src_ip"], packet["src_port"])
        return fwd in self.connections or rev in self.connections

    def is_anomalous(self, packet):
        """Detect TCP packets that do not fit an expected handshake state."""
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
        """Advance tracked TCP flow state based on the packet flags."""
        flags = set(packet.get("flags", []))
        fwd = self._key(packet)
        rev = (packet["dst_ip"], packet["dst_port"], packet["src_ip"], packet["src_port"])

        # A client-originated SYN starts tracking a new half-open connection.
        if "SYN" in flags and "ACK" not in flags:
            self.connections[fwd] = self.SYN_SENT

        # A valid SYN-ACK promotes the original client flow to established.
        elif "SYN" in flags and "ACK" in flags:
            if self.connections.get(rev) == self.SYN_SENT:
                self.connections[rev] = self.ESTABLISHED

        # The client's final ACK also marks the flow as established.
        elif "ACK" in flags:
            if self.connections.get(fwd) == self.SYN_SENT:
                self.connections[fwd] = self.ESTABLISHED
