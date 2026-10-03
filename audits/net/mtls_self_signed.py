# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024-2026 Block Harbor Cybersecurity LLC

from framework import *
import os
import time
import requests
import tempfile
from utils.netutil import temporary_static_ip


@register_audit("mtls_self_signed")
class mtls_self_signed(AuditRunner):
    parameters = [
        Parameter("iface", "Network Interface", "eth0", "The network interface on which to interact with the DNS Server"),
        Parameter("uri", "mTLS URI", "https://10.1.0.1:8883", "The URI of the mTLS Server to attempt to connect to"),
        Parameter("temp_ip", "Temporary IP", "", "A temporary IP address to set on the network interface, which will be reset after the test completes"),
        Parameter("temp_mask", "Temporary Subnet Mask", "255.255.255.0", "A temporary subnet mask to set on the network interface, which will be reset after the test completes"),
    ]
    dependencies = ['requests']
    friendly_name = "mTLS Self Signed Cert Connection"
    description = "Attempts to connect to a mutual TLS service with a self signed certificate and expects to be rejected for invalid credentials."
    fail_condition = "If any mTLS server accepts a connection with these invalid credentials the test will be marked failed."
    relevant_mitigations = ["M23"]
    relevant_interfaces = ["Automotive Ethernet", "WiFi", "Cellular"]
    bw_audit_id = "TS_NET_0013"
    estimated_time_in_minutes = "1"
    _client_cert = """\
-----BEGIN CERTIFICATE-----
MIIDLjCCAhYCFGZfu+blLjVWaL4D6BMOuNNXHE6LMA0GCSqGSIb3DQEBCwUAMEgx
CzAJBgNVBAYTAlVTMREwDwYDVQQIDAhNaWNoaWdhbjEQMA4GA1UEBwwHRGV0cm9p
dDEUMBIGA1UEAwwLZXhhbXBsZS5jb20wIBcNMjMwMjE1MTkwNjA1WhgPMjEyMzAx
MjIxOTA2MDVaMF0xCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhNaWNoaWdhbjEQMA4G
A1UEBwwHRGV0cm9pdDEVMBMGA1UECgwMQmxvY2sgSGFyYm9yMRIwEAYDVQQDDAls
b2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCTcHTvTy+p
Rd5ERlHwR/lhgL36wyMZ6XlsuTazJi99qH9ltcFYqog22WyBzAE3O7vuJSDEBT1m
ZU8tjeuAjpLS2P+ap8edYt58CyfR1b/UZp5p4/OyD8sNq473Wmu5Suqwc09sLLuU
96x6Us95cHcBk/fNyOqG+Q7mciDEXQbwpb2B8RZpmqTu+HTnxJglrEV3rnWKZJf1
EObCfXeknjKl6EDPGLJUYobbt6gou/I1ilRett0CIFKRfoOWwVE8M6mg1uupgIjF
PT3Fc9vztlMMKmu7FnePPbX2A/t3ucdG59b2870TzuknV0i1x8I0tWpGhom3ORLo
kw8P6zbFXvvLAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHWQm5mvjpnUrZMdAUpI
bIbR4V6YhhzQjVOPW0AB7Z+WCEe+aAYSkCFBT5Yi152iyWtYYq7AiExM+pWtLghY
uNr3oU+bI07JhYT+K7m4Eu6NOdb/qQoftPYzwqzymExYyO8H4sYU3k/21t+LZHta
5a69CubMKyakQjcKkXgBXOdaBrXvtuD57RFEQpSF+2AipVCDnXZLIcXdlDwzuLsy
5PBgNxW/o1bhBD85QdfwtEW+PaWGHONnxgt1IWYyZuIcJ9dmW2wXulqdQCgHwabo
f1OcAsZx9u4/HGF9+TJXgxux0kESSYYT3so18lwlnyNFS+JUsPg3hibbHPDl4BUZ
pPE=
-----END CERTIFICATE-----
"""
    _client_key = """\
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAk3B0708vqUXeREZR8Ef5YYC9+sMjGel5bLk2syYvfah/ZbXB
WKqINtlsgcwBNzu77iUgxAU9ZmVPLY3rgI6S0tj/mqfHnWLefAsn0dW/1GaeaePz
sg/LDauO91pruUrqsHNPbCy7lPeselLPeXB3AZP3zcjqhvkO5nIgxF0G8KW9gfEW
aZqk7vh058SYJaxFd651imSX9RDmwn13pJ4ypehAzxiyVGKG27eoKLvyNYpUXrbd
AiBSkX6DlsFRPDOpoNbrqYCIxT09xXPb87ZTDCpruxZ3jz219gP7d7nHRufW9vO9
E87pJ1dItcfCNLVqRoaJtzkS6JMPD+s2xV77ywIDAQABAoIBAQCIa5JW5x8DcdlR
tPsV55Kwi+28u5eb3zJxzgH1y0w/6YtPMdhfURLOJWlHw9oQIB4oIIRruylvuCeF
z/3qqoDhxNTkZX/GeXfAsJW8ixl+zyCee8O9qu1HjcivyCNKhC4Y6+i9/7nlATG+
0SaVh+ElPaMY7mFKV+JYiZsV9bl5KYpiUYYX70h5/u4ro9Z0JtwV/JShjjZtpiqy
mCbsoztoQEKLnztkOh2Mw7ByVP/oDxml3O1y5E/4IJ4FTCQOk5evuORoS6+D26b5
KdiUjyvzrvkkOoiTpiFmE0e0C6NOsRDL+dAxaT+2INbkjTgeBsuX9IuI657u0/R7
zIrW83DBAoGBAMN2a7Kz1ZRy8oScIWAQwBRLjUmfD39IsvPOogagKl4LTvSYAkaX
+aHjDQ9gt07zG7a/HZGytsFoRjiuMb6NKOoXPk03lp2lEN3it37Tb1osLrs0ZgER
cknvKO2cYPPvYafx4qyzYC4Y4OB+hLBtlKj089KNqUk+6aGvW0fwdukhAoGBAMEa
baQCRzWa0ImgGehfKx6sa5BYOTh0c8PtkUbOMccJmxJaXXaxjs1Ten5plt9UdFvE
6o+JtxLr9eFdvOD7DzsETliNyPkbDTxoQaX4S2T0lvGKH3gdsFBv44t/ZH9AqGca
35fjZXwRKpOklSQLS9ObrirK+23fXdpqnBsLIytrAoGBALc1JDVYAnUmWNKbVV0p
1iAvwLqk8G2pwrJrl8sGDTAhAVyZrmhkwoNOwksLqEXD8NIVyK1sCYi3KDqwa8fj
n9nq92aBGBejRG/1tXCW1eR7TUIDFykhJTLPjFlLHkUGt04nlwOxDhGnGADUFaMY
0yKaln9gcLBK28nFB5YiehKBAoGALJhM38aC6XdCV7Y4pXhs/d11zdUCCe6i2Ymg
tkhiKIQoYtmpogKpZvOzY0RBSnw3jwXv4Yw9UkpZ81zxhMeWIdwBt+OumRDNQrkV
CB5KUxtFTKzITbYVhM4CL7IQ5G5rNbx4DJzAUCGqwoQMyVEuhsT6OPm9jQc7pnhe
asRsr9cCgYEAmFJrsjYNhpj+wJ6Zu7RulLw6gOkZk6QU+id7PSjjecgPsvkOQuik
i3j2opofh/MEiWC/ELBvpj6bXKQggMCAv/Bk9+li7kLY3lNFrjBBNT08KmCdQruy
tzlnlqHu1sbxyqXW9kNUt0Itq8ivoz8f8Hl7iCkjdQxRBt8bHszGnQY=
-----END RSA PRIVATE KEY-----
"""
    _ca_cert = """\
-----BEGIN CERTIFICATE-----
MIIDczCCAlugAwIBAgIUbcKY5fcLmVNbUDOxWFXIm+k1EpAwDQYJKoZIhvcNAQEL
BQAwSDELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE1pY2hpZ2FuMRAwDgYDVQQHDAdE
ZXRyb2l0MRQwEgYDVQQDDAtleGFtcGxlLmNvbTAgFw0yMzAyMTUxODUzNTZaGA8y
MTIzMDEyMjE4NTM1NlowSDELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE1pY2hpZ2Fu
MRAwDgYDVQQHDAdEZXRyb2l0MRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMSXX02bTtv93ff33mepG9/UpDhLE/ol
hUbQKkJ4253wUtW3FxGCjfG1HNc6BHmxsNYT2clyC19nHOdPU//2KYqRiGPl6krc
fWRLd5T6XymM97ZhK8GhZBFjdHNOq7j1zOgkMLm88qDi27cULE0YKwQQW2IO3QBF
vS7n+z5mP1b4imWYZkInmRjLJ8Nx92tf7BUT9FEj6lpZdnBgX+eD48mdQuPdNO+Y
sSPev/NcHXZpUEfXZme5Rz6YgGsh/3i2fDxc0vTsQm9gXMMqYGEKy0JAcHKOva6C
V/vW4pHBZ0IBL94gCS4uh8BkN7ZvkqFzKnX0XuJtQHfqugWrmaRhHekCAwEAAaNT
MFEwHQYDVR0OBBYEFPM8W2qMW2QcWuFat3B2TKWV3mZ1MB8GA1UdIwQYMBaAFPM8
W2qMW2QcWuFat3B2TKWV3mZ1MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAHrM1z7pGJLdYRMboHLEahO2mG7nfg1fZodCPTDAivzR8az+toYu/GQi
W5N2TKGKp+Ocxuj0sTweK6Y8BWP2bzH6NHj+GSPT1UZvQVAVzuLX09rN3VWIzIZ4
sPK7P4zbUxSCz/Er/C95c1hTWvHiO0s6zlrjUv6yyDDxbnk4ZcYMZ8zphBHYhjd6
52fn9c1mC3hIHjajARqPpZwkjOe7awrxTG1wdURR4ztxon/CII/W1Tt9AbCFgwi0
SaUi1OoRuax8ZNRfk3Lbg++cAvo50G+FuzGvliGzx0hYJtFvLTO9Ca9+YKvSarxG
zzptO8rD6iA4SbP4KdDrThFOXAwM+oA=
-----END CERTIFICATE-----
"""
    test_outcomes = {
        "SUCCESS": {
            "description": "The specified mTLS server is enforcing client authentication and rejects self signed client certificates.",
            "recommendations": []
        },
        "NO_RESPONSE": {
            "description": "The test failed to communicate with the specified `target_host`",
            "recommendations": [
                "Check test parameters, physical connections and device power.",
            ]
        },
        "FAILURE": {
            "description": "The specified mTLS server allows authentication with self signed client certificates.",
            "recommendations": [
                "Review the destination of the offending TLS connection and modify that server's configuration."
            ]
        }
    }

    def run_audit(self):
        import os
        import tempfile
        import time
        import requests

        target = self.params["uri"]

        self.temp_ip = temporary_static_ip(
            self.params["iface"],
            self.params["temp_ip"],
            self.params["temp_mask"],
            self.log,
        )

        segments = []
        severity = "n/a"
        tmp_files = []
        try:
            def write_tmp(content):
                f = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)
                f.write(content)
                f.flush()
                f.close()
                tmp_files.append(f.name)
                return f.name

            client_cert = write_tmp(self._client_cert)
            client_key = write_tmp(self._client_key)

            requests.get(target, cert=(client_cert, client_key), verify=False)

            segments.append(
                Report.create_text_segment("Connection succeeded, test FAILED!")
            )
            severity = "medium"
        except requests.exceptions.SSLError as e:
            segments.append(
                Report.create_text_segment("SSL Error encountered:" + str(e))
            )
        except Exception as e:
            segments.append(
                Report.create_text_segment("Other exception encountered:" + str(e))
            )
        finally:
            for f in tmp_files:
                try:
                    os.unlink(f)
                except Exception:
                    pass

        title = "mTLS Self Signed Certificate"
        if severity == "n/a":
            segments.append(
                Report.create_text_segment(f"Failed to authenticate, Test Passed")
            )
        else:
            segments.append(Report.create_text_segment(f"Authenticated, Test FAILED"))

        return {
            "title": title,
            "segments": segments,
            "pass_rules": {"vulnerable": (severity != "n/a")},
        }

    def format_results(self, results):
        return [{"title": results["title"], "segments": results["segments"]}]
