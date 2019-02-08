from getgauge.python import step, before_scenario, Messages
import requests
import os
import urllib

# --------------------------
# Gauge step implementations
# --------------------------

@step("Authenticate against restful API with key <api_key> at endpoint <url> then fuzz endpoint with 100 requests starting with seed <seed>.")
def perform_step_mailgun_api_fuzz(api_key,url,seed):
    ct = 0
    while (ct < 5):
        ct += 1
        seed = os.system("echo '{}' | radamsa".format(seed))
        fuzzywuzzy = requests.post(
            "{}",
            auth=("api", "{}"),
            data={"from": "Excited User <postmaster@sandbox7abd1c86e8604bbfb004769a1e64b241.mailgun.org>",
                  "to": ["User", "{}"],
                  "subject": "Hello",
                  "text": "Test email"}.format(url,api_key,seed))
        fuzzywuzzy_stats = fuzzywuzzy.status_code
        if fuzzywuzzy_stats == 200:
            print("Passed")
        else:
            print("Failed")
