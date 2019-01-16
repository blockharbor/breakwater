
import requests
from openvas_lib import VulnscanManager, VulnscanException
from getgauge.python import step, before_scenario, Messages
sys.path.append('/Users/brandonbarry/blockharbor/breakwater/gauge-python-security-tests/credentials')
import openvas_creds

# --------------------------
# Gauge step implementations
# --------------------------

@step("OpenVAS vulnerability scan network host: <ipAddr>.")
def assert_openvas(ipAddr):
    HOST = "" #Local IP address of OpenVAS server.
    PORT = "" #Local Port of OpenVAS server.
    TIMEOUT = "" 
    try:
        scanner = VulnscanManager(HOST, openvas_creds.user, openvas_creds.password, PORT, TIMEOUT)
        scan_id, target_id = scanner.launch_scan(target = ipAddr, profile = "Full and fast")
    except VulnscanException as e:
    print("Error:")
    print(e)

# ---------------
# Execution Hooks
# ---------------
