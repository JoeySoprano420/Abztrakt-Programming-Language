from concurrent.futures import ThreadPoolExecutor

def execute_packet(packet):
    print(f"Executing: {packet.action} with data {packet.data}")
    # Simulate some work
    import time
    time.sleep(1)

# Using ThreadPoolExecutor for concurrent packet execution
executor = ThreadPoolExecutor(max_workers=5)
packets = [ExecutionPacket("secure", "encrypt", "data", {"key": "public-key"}) for _ in range(10)]

# Execute packets concurrently
executor.map(execute_packet, packets)
