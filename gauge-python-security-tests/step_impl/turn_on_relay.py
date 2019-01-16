from getgauge.python import step, before_scenario, Messages

# --------------------------
# Gauge step implementations
# --------------------------

@step("Turn on relay: <relay_num>.")
def turn_on_relay(relay_num):
    #TODO: Implement hardware interface to relays to boot system up. 
    assert relay_num == "5"

# ---------------
# Execution Hooks
# ---------------

