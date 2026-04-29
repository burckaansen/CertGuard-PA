# ASCII only

import servicemanager
import win32event
import win32service
import win32serviceutil


SERVICE_NAME = "CertGuard-PA"
SERVICE_DISPLAY_NAME = "CertGuard-PA Certificate Monitor"
SERVICE_DESCRIPTION = "CertGuard-PA automated Palo Alto certificate lifecycle monitor."


def log_info(message):
    try:
        from certguard_agent import log
        log(message, "INFO", 300)
    except Exception:
        servicemanager.LogInfoMsg(f"[CertGuard-PA] {message}")


def log_error(message):
    try:
        from certguard_agent import log
        log(message, "ERROR", 304)
    except Exception:
        servicemanager.LogErrorMsg(f"[CertGuard-PA] {message}")


class CertGuardPAService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = SERVICE_DESCRIPTION

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running = True

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.running = False
        win32event.SetEvent(self.stop_event)
        log_info("Service stop requested")

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        log_info("Service started")
        self.main_loop()

    def main_loop(self):
        while self.running:
            interval = 3600
            try:
                from certguard_agent import load_config, service_tick
                service_tick()
                interval = int(load_config().get("service", {}).get("interval_seconds", 3600))
                if interval < 30:
                    interval = 30
            except Exception as exc:
                log_error(str(exc))
            wait_result = win32event.WaitForSingleObject(self.stop_event, interval * 1000)
            if wait_result == win32event.WAIT_OBJECT_0:
                break
        log_info("Service stopped")


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(CertGuardPAService)
