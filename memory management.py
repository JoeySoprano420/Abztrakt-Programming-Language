class MemoryPool:
    def __init__(self, pool_size):
        self.pool_size = pool_size
        self.pool = []
        self.available = []

    def allocate(self):
        if not self.available:
            return self._create_new_packet()
        return self.available.pop()

    def deallocate(self, packet):
        self.available.append(packet)

    def _create_new_packet(self):
        if len(self.pool) < self.pool_size:
            packet = ExecutionPacket("secure", "default", "default", {"key": "default"})
            self.pool.append(packet)
            return packet
        else:
            raise MemoryError("Memory Pool Overflow")

# Usage
memory_pool = MemoryPool(10)
packet = memory_pool.allocate()
memory_pool.deallocate(packet)
