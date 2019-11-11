from getgauge.python import step, before_scenario, Messages
import os,sys



# --------------------------
# Gauge step implementations
# --------------------------

@step("Set up <vehicle> with bitrate <bitrate>.")
def vehicle_setup(vehicle, bitrate):
    print "\n\nStarting output for Gauge execution.\n\n"
    print "\n\nSETTING UP "+vehicle+".\n\n" 
    os.system("tools/"+vehicle+"_setup/"+vehicle+"_setup.sh")
    assert 1 == 1


# ---------------
# Execution Hooks
# ---------------

