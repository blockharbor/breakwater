
import requests
import nmap
from getgauge.python import step, before_scenario, Messages


# --------------------------
# Gauge step implementations
# --------------------------

@step("Scan network host: <ipAddr> on ports: <ports>.")
def assert_nmap(ipAddr, ports):
    print(ipAddr, ports)
    nm = nmap.PortScanner()
    nm.scan(str(ipAddr), str(ports))
    print(nm.csv())
    assert nm[str(ipAddr)].state() == "up"


# ---------------
# Execution Hooks
# ---------------
