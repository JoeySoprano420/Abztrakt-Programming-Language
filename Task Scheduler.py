import queue

class TaskScheduler:
    def __init__(self):
        self.task_queue = queue.Queue()

    def add_task(self, packet):
        self.task_queue.put(packet)

    def dispatch(self):
        while not self.task_queue.empty():
            packet = self.task_queue.get()
            packet.execute()

# Example task scheduler usage
scheduler = TaskScheduler()
scheduler.add_task(ExecutionPacket("secure", "encrypt", "data", {"key": "public-key"}))
scheduler.add_task(ExecutionPacket("validate", "checksum", "data"))

# Dispatch tasks
scheduler.dispatch()
