#!/usr/bin/env python3

import argparse,json,requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def icontrol_get(host,username,password,path):
    apiCall = requests.session()
    apiCall.headers.update({'Content-type':'application/json'})
    apiCall.auth = (username,password)
    apiUri = 'https://' + host + path
    try:
        apiResponse = apiCall.get(apiUri,verify=False)
    except requests.exceptions.RequestException as e:
        print('{"responseStatus":"error","action":"get","host":"' + host + '","username":"' + username + '","path":"' + path + '","errorMsg":"' + str(e) + '"}')
    return(apiResponse.text)

def icontrol_post(host,username,password,path,api_payload):
    apiCall = requests.session()
    apiCall.headers.update({'Content-type':'application/json'})
    apiCall.auth = (username,password)
    apiUri = 'https://' + host + path
    try:
        apiResponse = apiCall.post(apiUri,verify=False,data=json.dumps(api_payload))
    except requests.exceptions.RequestException as e:
        print('{"responseStatus":"error","action":"post","host":"' + host + '","username":"' + username + '","path":"' + path + '"},"payload":"' + api_payload + '","errorMsg":"' + str(e) + '"}')
    return(apiResponse.text)

def icontrol_put(host,username,password,path,api_payload):
    apiCall = requests.session()
    apiCall.headers.update({'Content-type':'application/json'})
    apiCall.auth = (username,password)
    apiUri = 'https://' + host + path
    try:
        apiResponse = apiCall.put(apiUri,verify=False,data=json.dumps(api_payload))
    except requests.exceptions.RequestException as e:
        print('{"responseStatus":"error","action":"put","host":"' + host + '","username":"' + username + '","path":"' + path + '"},"payload":"' + api_payload + '","errorMsg":"' + str(e) + '"}')
    return(apiResponse.text)

def icontrol_patch(host,username,password,path,api_payload):
    apiCall = requests.session()
    apiCall.headers.update({'Content-type':'application/json'})
    apiCall.auth = (username,password)
    apiUri = 'https://' + host + path
    try:
        apiResponse = apiCall.patch(apiUri,verify=False,data=json.dumps(api_payload))
    except requests.exceptions.RequestException as e:
        print('{"responseStatus":"error","action":"patch","host":"' + host + '","username":"' + username + '","path":"' + path + '"},"payload":"' + api_payload + '","errorMsg":"' + str(e) + '"}')
    return(apiResponse.text)

def icontrol_delete(host,username,password,path):
    apiCall = requests.session()
    apiCall.headers.update({'Content-type':'application/json'})
    apiCall.auth = (username,password)
    apiUri = 'https://' + host + path
    try:
        apiResponse = apiCall.delete(apiUri,verify=False)
    except requests.exceptions.RequestException as e:
        print('{"responseStatus":"error","action":"delete","host":"' + host + '","username":"' + username + '","path":"' + path + '"},"errorMsg":"' + str(e) + '"}')
    return(apiResponse.text)

#
# Parse the command line arguments
#

cmdargs = argparse.ArgumentParser()
cmdargs.add_argument('--host',action='store',required=True,type=str,help='ip of BIG-IP REST interface, typically the mgmt ip')
cmdargs.add_argument('--username',action='store',required=True,type=str,help='username for REST authentication')
cmdargs.add_argument('--password',action='store',required=True,type=str,help='password for REST authentication')
cmdargs.add_argument('--licensekey',action='store',required=False,type=str,help='license key for licensing')
cmdargs.add_argument('--hostname',action='store',required=False,type=str,help='hostname to configure on the BIG-IP')
cmdargs.add_argument('--ntpserver',action='store',required=False,type=str,help='NTP server to add to the BIG-IP')
cmdargs.add_argument('--vpn-localselfip',action='store',required=True,type=str,help='the private self-ip address of the VE where the public address is mapped')
cmdargs.add_argument('--vpn-localpublicip',action='store',required=True,type=str,help='the public IP address of the VNA')
cmdargs.add_argument('--vpn-remotepublicip',action='store',required=True,type=str,help='the public IP address of the remote IPSec peer')
cmdargs.add_argument('--vpn-presharedkey',action='store',required=True,type=str,help='the pre-shared key for encryption')
cmdargs.add_argument('--vpn-tunnelname',action='store',required=True,type=str,help='a name for the new tunnel')

parsed_args = cmdargs.parse_args()

host = parsed_args.host
username = parsed_args.username
password = parsed_args.password
license_key = parsed_args.licensekey
hostname = parsed_args.hostname
ntpserver = parsed_args.ntpserver
vpn['local-self-ip'] = parsed_args.vpn-localselfip
vpn['local-public-ip'] = parsed_args.vpn-localpublicip
vpn['remote-public-ip'] = parsed_args.vpn-remotepublicip
vpn['pre-shared-key'] = parsed_args.vpn-presharedkey
vpn['tunnel-name'] = parsed_args.vpn-tunnelname
if license_key is not None:
    print('Licensing ' + host + ' with key ' + license_key)
    apiCallResponse = icontrol_post(host,username,password,'/mgmt/tm/sys/license','{"command":"install","registrationKey":"' + license_key + '"}')
    if '"commandResult":"New license installed\n"' in apiCallResponse:
        print('License installed successfully.')
else:
    print("License key not specified - skipping licensing")

print('Disabling the GUI Setup Wizard')
apiCallResponse = icontrol_patch(host,username,password,'/mgmt/tm/sys/global-settings','{"guiSetup":"disabled"}')
if '"kind":"tm:sys:global-settings:global-settingsstate"' and '"guiSetup":"disabled"' in apiCallResponse:
    print('Success!')

if hostname is not None:
    print('Setting the hostname to ' + hostname + ' on ' + host)
    apiCallResponse = icontrol_patch(host, username, password, '/mgmt/tm/sys/global-settings','{"hostname":"' + hostname + '"}')
    if '"kind":"tm:sys:global-settings:global-settingsstate"' and '"hostname":"' + hostname + '"' in apiCallResponse:
        print('Success!')
else:
    print('Hostname not specified - skipping hostname configuration')

if ntpserver is not None:
    print('Adding NTP server ' + ntpserver + ' to ' + host)
    apiCallResponse = icontrol_patch(host,username,password,'/mgmt/tm/sys/ntp','{"servers":["' + ntpserver + '"]}')
    if '"kind":"tm:sys:ntp:ntpstate"' in apiCallResponse:
        print('Success!')
else:
    print('NTP server not specified - skipping NTP server configuration')

print('Creating the IPSec Policy')
apiCallResponse = icontrol_post(host,username,password,'/mgmt/tm/net/ipsec/ipsec-policy','{"name":"comcast-xre-vpn","ike-phase2-auth-algorithm":"sha256","ike-phase2-encrypt-algorithm":"aes256","ike-phase2-perfect-forward-secrecy":"modp1024","mode":"interface"}')
if '"kind":"tm:net:ipsec:ipsec-policy:ipsec-policystate"' in apiCallResponse:
    print('Success!')
"""
9. Create the IPSec Policy

curl -sk -H "Content-type: application/json" -u comcast:Password.12345 https://40.112.139.199/mgmt/tm/net/ipsec/ipsec-policy -X POST -d '

RESPONSE: {"kind":"tm:net:ipsec:ipsec-policy:ipsec-policystate","name":"comcast-xre-vpn","partition":"Common","fullPath":"/Common/comcast-xre-vpn","generation":25,"selfLink":"https://localhost/mgmt/tm/net/ipsec/ipsec-policy/~Common~comcast-xre-vpn?ver=12.1.2","ikePhase2AuthAlgorithm":"sha256","ikePhase2EncryptAlgorithm":"aes256","ikePhase2Lifetime":1440,"ikePhase2LifetimeKilobytes":0,"ikePhase2PerfectForwardSecrecy":"modp1024","ipcomp":"none","mode":"interface","protocol":"esp","tunnelLocalAddress":"any6","tunnelRemoteAddress":"any6"}

10. Create the IPSec Traffic Selector

curl -sk -H "Content-type: application/json" -u comcast:Password.12345 https://40.112.139.199/mgmt/tm/net/ipsec/traffic-selector -X POST -d '{"name":"comcast-xre-vpn","action":"protect","destinationAddress":"0.0.0.0/0","destinationPort":0,"sourceAddress":"0.0.0.0/0","sourcePort":0,"order":0,"ipsecPolicy":"comcast-xre-vpn"}'

RESPONSE: {"kind":"tm:net:ipsec:traffic-selector:traffic-selectorstate","name":"comcast-xre-vpn","partition":"Common","fullPath":"/Common/comcast-xre-vpn","generation":26,"selfLink":"https://localhost/mgmt/tm/net/ipsec/traffic-selector/~Common~comcast-xre-vpn?ver=12.1.2","action":"protect","destinationAddress":"0.0.0.0/0","destinationPort":0,"direction":"both","ipProtocol":255,"ipsecPolicy":"/Common/comcast-xre-vpn","ipsecPolicyReference":{"link":"https://localhost/mgmt/tm/net/ipsec/ipsec-policy/~Common~comcast-xre-vpn?ver=12.1.2"},"order":0,"sourceAddress":"0.0.0.0/0","sourcePort":0}

11. Set the default IPSec traffic selector to higher order

curl -sk -H "Content-type: application/json" -u comcast:Password.12345 https://40.112.139.199/mgmt/tm/net/ipsec/traffic-selector/default-traffic-selector-interface -X PATCH -d '{"order":1}'

{"kind":"tm:net:ipsec:traffic-selector:traffic-selectorstate","name":"default-traffic-selector-interface","fullPath":"default-traffic-selector-interface","generation":28,"selfLink":"https://localhost/mgmt/tm/net/ipsec/traffic-selector/default-traffic-selector-interface?ver=12.1.2","action":"protect","destinationAddress":"::/0","destinationPort":0,"direction":"both","ipProtocol":255,"ipsecPolicy":"/Common/default-ipsec-policy-interface","ipsecPolicyReference":{"link":"https://localhost/mgmt/tm/net/ipsec/ipsec-policy/~Common~default-ipsec-policy-interface?ver=12.1.2"},"order":1,"sourceAddress":"::/0","sourcePort":0}

12. Create IKE Peer

curl -sk -H "Content-type: application/json" -u comcast:Password.12345 https://40.112.139.199/mgmt/tm/net/ipsec/ike-peer -X POST -d '{"name":"comcast-xre-vpn","myIdType":"address","myIdValue":"40.112.139.199","peersIdType":"address","peersIdValue":"98.114.173.215","phase1AuthMethod":"pre-shared-key","phase1EncryptAlgorithm":"aes256","phase1HashAlgorithm":"sha256","phase1PerfectForwardSecrecy":"modp1024","prf":"sha256","presharedKey":"myTunnel1234!","remoteAddress":"98.114.173.215","version":["v2"],"dpdDelay":30,"lifetime":1440,"mode":"main","natTraversal":"off","passive":"false","generatePolicy":"off","trafficSelector":["comcast-xre-vpn"]}'

RESPONSE: {"kind":"tm:net:ipsec:ike-peer:ike-peerstate","name":"comcast-xre-vpn","partition":"Common","fullPath":"/Common/comcast-xre-vpn","generation":33,"selfLink":"https://localhost/mgmt/tm/net/ipsec/ike-peer/~Common~comcast-xre-vpn?ver=12.1.2","dpdDelay":30,"generatePolicy":"off","lifetime":1440,"mode":"main","myIdType":"address","myIdValue":"40.112.139.199","natTraversal":"off","passive":"false","peersCertType":"none","peersIdType":"address","peersIdValue":"98.114.173.215","phase1AuthMethod":"pre-shared-key","phase1EncryptAlgorithm":"aes256","phase1HashAlgorithm":"sha256","phase1PerfectForwardSecrecy":"modp1024","presharedKeyEncrypted":"$M$kg$FeIo0kbjr9XJq+wsRXJFkQ==","prf":"sha256","proxySupport":"enabled","remoteAddress":"98.114.173.215","replayWindowSize":64,"state":"enabled","trafficSelector":["/Common/comcast-xre-vpn"],"trafficSelectorReference":[{"link":"https://localhost/mgmt/tm/net/ipsec/traffic-selector/~Common~comcast-xre-vpn?ver=12.1.2"}],"verifyCert":"false","version":["v2"]}

13. Create tunnel profile

curl -sk -H "Content-type: application/json" -u comcast:Password.12345 https://40.112.139.199/mgmt/tm/net/tunnels/ipsec -X POST -d '{"name":"comcast-xre-vpn","trafficSelector":"comcast-xre-vpn"}'

RESPONSE: {"kind":"tm:net:tunnels:ipsec:ipsecstate","name":"comcast-xre-vpn","partition":"Common","fullPath":"/Common/comcast-xre-vpn","generation":34,"selfLink":"https://localhost/mgmt/tm/net/tunnels/ipsec/~Common~comcast-xre-vpn?ver=12.1.2","defaultsFrom":"/Common/ipsec","defaultsFromReference":{"link":"https://localhost/mgmt/tm/net/tunnels/ipsec/~Common~ipsec?ver=12.1.2"},"trafficSelector":"/Common/comcast-xre-vpn","trafficSelectorReference":{"link":"https://localhost/mgmt/tm/net/ipsec/traffic-selector/~Common~comcast-xre-vpn?ver=12.1.2"}}

14. Create the tunnel

curl -sk -H "Content-type: application/json" -u comcast:Password.12345 https://40.112.139.199/mgmt/tm/net/tunnels/tunnel -X POST -d '{"name":"comcast-xre-vpn","idleTimeout": 300,"mode": "bidirectional","profile":"comcast-xre-vpn","tos": "preserve","localAddress":"10.0.0.4","remoteAddress":"98.114.173.215"}'

RESPONSE: {"kind":"tm:net:tunnels:tunnel:tunnelstate","name":"comcast-xre-vpn","partition":"Common","fullPath":"/Common/comcast-xre-vpn","generation":35,"selfLink":"https://localhost/mgmt/tm/net/tunnels/tunnel/~Common~comcast-xre-vpn?ver=12.1.2","autoLasthop":"default","idleTimeout":300,"ifIndex":128,"key":0,"localAddress":"10.0.0.4","mode":"bidirectional","mtu":0,"profile":"/Common/comcast-xre-vpn","profileReference":{"link":"https://localhost/mgmt/tm/net/tunnels/ipsec/~Common~comcast-xre-vpn?ver=12.1.2"},"remoteAddress":"98.114.173.215","secondaryAddress":"any6","tos":"preserve","transparent":"disabled","usePmtu":"enabled"}

15. Create the self-IP for the tunnel route

curl -sk -H "Content-type: application/json" -u comcast:Password.12345 https://40.112.139.199/mgmt/tm/net/self -X POST -d '{"name":"comcast-xre-vpn","address":"1.1.1.1/32","vlan":"comcast-xre-vpn","traffic-group":"traffic-group-local-only","allowService":"all"}'

RESPONSE: {"kind":"tm:net:self:selfstate","name":"comcast-xre-vpn","partition":"Common","fullPath":"/Common/comcast-xre-vpn","generation":40,"selfLink":"https://localhost/mgmt/tm/net/self/~Common~comcast-xre-vpn?ver=12.1.2","address":"1.1.1.1/32","addressSource":"from-user","floating":"disabled","inheritedTrafficGroup":"false","trafficGroup":"/Common/traffic-group-local-only","trafficGroupReference":{"link":"https://localhost/mgmt/tm/cm/traffic-group/~Common~traffic-group-local-only?ver=12.1.2"},"unit":0,"vlan":"/Common/comcast-xre-vpn","vlanReference":{"link":"https://localhost/mgmt/tm/net/tunnels/tunnel/~Common~comcast-xre-vpn?ver=12.1.2"},"allowService":"all"}

16. Create the static route for the tunnel

curl -sk -H "Content-type: application/json" -u comcast:Password.12345 https://40.112.139.199/mgmt/tm/net/route -X POST -d '{"name":"comcast-xre-vpn","tmInterface": "/Common/comcast-xre-vpn","network": "10.0.0.0/8","mtu":0}'

RESPONSE: {"kind":"tm:net:route:routestate","name":"comcast-xre-vpn","partition":"Common","fullPath":"/Common/comcast-xre-vpn","generation":43,"selfLink":"https://localhost/mgmt/tm/net/route/~Common~comcast-xre-vpn?ver=12.1.2","tmInterface":"/Common/comcast-xre-vpn","tmInterfaceReference":{"link":"https://localhost/mgmt/tm/net/tunnels/tunnel/~Common~comcast-xre-vpn?ver=12.1.2"},"mtu":0,"network":"10.0.0.0/8"}

17. Create the IP forwarding virtual listener

curl -sk -H "Content-type: application/json" -u comcast:Password.12345 https://40.112.139.199/mgmt/tm/ltm/virtual -X POST -d '{"name":"ip_forwarding_vs","destination":"/Common/0.0.0.0:0","ipProtocol":"any","mask":"255.255.255.255","source":"0.0.0.0/0","sourceAddressTranslation":{"type":"none"},"sourcePort":"preserve","profiles":["fastL4"]}'

RESPONSE: {"kind":"tm:ltm:virtual:virtualstate","name":"ip_forwarding_vs","partition":"Common","fullPath":"/Common/ip_forwarding_vs","generation":46,"selfLink":"https://localhost/mgmt/tm/ltm/virtual/~Common~ip_forwarding_vs?ver=12.1.2","addressStatus":"yes","autoLasthop":"default","cmpEnabled":"yes","connectionLimit":0,"destination":"/Common/0.0.0.0:0","enabled":true,"gtmScore":0,"ipProtocol":"any","mask":"255.255.255.255","mirror":"disabled","mobileAppTunnel":"disabled","nat64":"disabled","rateLimit":"disabled","rateLimitDstMask":0,"rateLimitMode":"object","rateLimitSrcMask":0,"serviceDownImmediateAction":"none","source":"0.0.0.0/0","sourceAddressTranslation":{"type":"none"},"sourcePort":"preserve","synCookieStatus":"not-activated","translateAddress":"disabled","translatePort":"disabled","vlansDisabled":true,"vsIndex":5,"policiesReference":{"link":"https://localhost/mgmt/tm/ltm/virtual/~Common~ip_forwarding_vs/policies?ver=12.1.2","isSubcollection":true},"profilesReference":{"link":"https://localhost/mgmt/tm/ltm/virtual/~Common~ip_forwarding_vs/profiles?ver=12.1.2","isSubcollection":true}}

18. Save the configuration

curl -sk -H "Content-type: application/json" -u comcast:Password.12345 https://40.112.139.199/mgmt/tm/sys/config -X POST -d '{"command":"save"}'

RESPONSE: {"kind":"tm:sys:config:savestate","command":"save"}

"""