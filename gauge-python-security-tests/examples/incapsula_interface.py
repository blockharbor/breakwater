
import requests
from getgauge.python import step, before_scenario, Messages


# --------------------------
# Gauge step implementations
# --------------------------

@step("The url: <url> is protected by Incapsula.")
def assert_incapsula(url):
    resp = requests.get(url)
    assert resp.headers['X-CDN'] == "Incapsula"


# ---------------
# Execution Hooks
# ---------------
