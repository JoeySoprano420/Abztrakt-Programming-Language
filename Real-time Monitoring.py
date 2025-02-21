import time
import threading

class RealTimeMonitor:
    def __init__(self):
        self.errors = []
        self.execution_time = 0
        self.packet_count = 0

    def start_monitoring(self):
        self.monitor_thread = threading.Thread(target=self.monitor)
        self.monitor_thread.start()

    def monitor(self):
        while True:
            print(f"Executing {self.packet_count} packets...")
            time.sleep(1)

    def log_error(self, error):
        self.errors.append(error)
        print(f"Error: {error}")

    def log_execution_time(self, time_spent):
        self.execution_time += time_spent
        print(f"Execution Time: {self.execution_time} seconds")

    def increment_packet_count(self):
        self.packet_count += 1

# Example monitor usage
monitor = RealTimeMonitor()
monitor.start_monitoring()

# Simulate execution and logging
for i in range(5):
    monitor.increment_packet_count()
    monitor.log_execution_time(1)
    time.sleep(1)
    monitor.log_error("Sample error")
