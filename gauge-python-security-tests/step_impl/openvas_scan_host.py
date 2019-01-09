
import requests
import nmap
from getgauge.python import step, before_scenario, Messages


# --------------------------
# Gauge step implementations
# --------------------------

@step("Scan network host: <ipAddr> on ports: <ports>.")
def assert_nmap(url):
    nm = nmap.PortScanner()
    nm.scan(ipAddr, ports)
    assert resp.headers['X-CDN'] == "Incapsula"


# ---------------
# Execution Hooks
# ---------------
