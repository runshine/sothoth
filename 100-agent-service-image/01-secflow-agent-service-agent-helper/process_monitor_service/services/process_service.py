from process_monitor_service.monitor import ProcessService
from process_monitor_service.config import settings

process_service = ProcessService()
process_service.settings = settings
process_service.start()
