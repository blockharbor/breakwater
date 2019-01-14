
import requests
import nmap
import tenable_io
import sys
sys.path.append('../credentials/')
import tenable_io_creds
from tenable_io.client import TenableIOClient
from tenable_io.api.models import Scan
from tenable_io.api.scans import ScanExportRequest
from tenable_io.client import TenableIOClient
from tenable_io.exceptions import TenableIOApiException
from getgauge.python import step, before_scenario, Messages


# --------------------------
# Gauge step implementations
# --------------------------

@step("Vulnerability scan network host: <ipAddr>.")
def assert_nessus(ipAddr):
    '''
    # Generate unique name and file. Base this off of IP, date/time? Test, for now.
    '''

    scan_name = u'example scan'
    test_pdf_file = u'example_report.pdf'

    '''
    Instantiate an instance of the TenableIOClient.
    '''

    client = TenableIOClient(access_key=tenable_io_creds.access_key, secret_key=tenable_io_creds.secret_key)

    '''
    Create a scan. In this case, I chose a basic scan against the given ipAddr

    MISSING: Need to specify scanner to use.
    '''

    scan = client.scan_helper.create(
        name=scan_name,
        text_targets=ipAddr,
        template='basic'
    )
    assert scan.name() == scan_name

    '''
    Launch a scan, then download when scan is completed (this function blocks. Execution time can be long.).
    '''

    scan.launch().download(test_pdf_file)
    first_scan_history_id = min([int(history.history_id) for history in scan.histories()])
    assert os.path.isfile(test_pdf_file)

    



# ---------------
# Execution Hooks
# ---------------
