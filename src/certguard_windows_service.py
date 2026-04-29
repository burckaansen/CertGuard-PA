# ASCII only

import servicemanager
import win32event
import win32service
import win32serviceutil

from certguard_agent import load_config, log, service_tick


SERVICE_NAME = "CertGuard-PA"
SERVICE_DISPLAY_NAME = "CertGuard-PA Certificate Monitor"
SERVICE_DESCRIPTION = "CertGuard-PA automated Palo Alto certificate lifecycle monitor."


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
        log("Service stop requested", "INFO", 300)

    def SvcDoRun(self):
        servicemanager.LogInfoMsg("CertGuard-PA service started")
        log("Service started", "INFO", 300)
        while self.running:
            try:
                service_tick()
            except Exception as exc:
                log(f"Service loop error: {exc}", "ERROR", 304)
            interval = int(load_config().get("service", {}).get("interval_seconds", 3600))
            if interval < 30:
                interval = 30
            wait_result = win32event.WaitForSingleObject(self.stop_event, interval * 1000)
            if wait_result == win32event.WAIT_OBJECT_0:
                break
        log("Service stopped", "INFO", 300)


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(CertGuardPAService)
