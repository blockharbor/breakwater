# Security Check Network Device

This is an executable specification file. This file follows markdown syntax.
Every heading in this file denotes a scenario. Every bulleted point denotes a step.

To execute this specification, run

    gauge run specs


Verify the IP address is on the network, and port scan it.
Once open ports are outlined and the host is confirmed to be up, run vulnerability scans against the host using OpenVAS and Nessus.


## TODO: Start up devices. 

* Turn on relay: "5". 

## NMAP Scan

* Scan network host: "172.22.22.22" on ports: "2-1000".

## Nessus Scan

* Nessus vulnerability scan network host: "172.22.22.22".

## OpenVAS Scan

* OpenVAS vulnerability scan network host: "172.22.22.22".
