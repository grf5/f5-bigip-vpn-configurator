Configuration script for F5 BIG-IP VPN endpoint

This script configures a "raw" BIG-IP TMOS instance, complete with licensing, for a VPN endpoint. This was tested on TMOS 13.0 in Azure for a cloud overlay project.

usage: vpn-configurator.py --host 192.168.1.1 --username admin --password helloworld! [--licensekey ABCD-EFGH-IJKL-MNOP-QRST-BANA-NANA] [--hostname mybigip.lab] [--ntpserver 0.pool.ntp.org] --localselfip 10.0.0.1 --localpublicip 192.88.99.34 --remotepublicip 198.51.100.95 --presharedkey applesANDbananas --tunnelsourcenet 0.0.0.0/0 --tunneldestinationnet 0.0.0.0/0 --tunnelselfip 172.16.1.1/32

