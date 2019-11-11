# Specification Heading

This is an executable specification file. This file follows markdown syntax.
Every heading in this file denotes a scenario. Every bulleted point denotes a step.

To execute this specification, run

    gauge run specs

## Setup Vehicle with proper parameters.
* Set up "vehicle_2" with bitrate "500000".

## CAN test on Vehicle to verify connectivity.
* Execute CAN test on interface "vcan0".


## Scan for UDS services on Vehicle.
* Execute UDS scan on interface "vcan0". 

