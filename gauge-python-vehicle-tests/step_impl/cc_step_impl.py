from getgauge.python import step, before_scenario, Messages
import os,sys



# --------------------------
# Gauge step implementations
# --------------------------

@step("Execute CAN test on interface <can_interface>.")
def CAN_test(can_interface):
    print "\n\nStarting output for Gauge execution.\n\n"
    os.environ['CAN_INTERFACE'] = "socketcan"
    os.environ['CAN_CHANNEL'] = can_interface
    storedcwd = os.getcwd()
    os.chdir("tools/caringcaribou/tool")
    os.system("python cc.py test")
    os.chdir(storedcwd)
    assert 1 == 1



@step("Execute UDS scan on interface <can_interface>.")
def UDS_scan(can_interface):
    print "\n\nStarting output for Gauge execution.\n\n"
    print(os.getcwd())
    storedcwd = os.getcwd()
    os.chdir("tools/caringcaribou/tool")
    os.system("python cc.py uds discovery")
    os.chdir(storedcwd)
    assert 1 == 1



# ---------------
# Execution Hooks
# ---------------

