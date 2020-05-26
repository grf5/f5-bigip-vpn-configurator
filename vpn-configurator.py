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
cmdargs.add_argument('--localselfip',action='store',required=True,type=str,help='the private self-ip address of the VE where the public address is mapped')
cmdargs.add_argument('--localpublicip',action='store',required=True,type=str,help='the public IP address of the VNA')
cmdargs.add_argument('--remotepublicip',action='store',required=True,type=str,help='the public IP address of the remote IPSec peer')
cmdargs.add_argument('--presharedkey',action='store',required=True,type=str,help='the pre-shared key for encryption')
cmdargs.add_argument('--tunnelsourcenet',action='store',required=True,type=str,help='CIDR notated source network')
cmdargs.add_argument('--tunneldestinationnet',action='store',required=True,type=str,help='CIDR notated destination network')
cmdargs.add_argument('--tunnelselfiplocal',action='store',required=True,type=str,help='CIDR notated tunnel self-IP address')

parsed_args = cmdargs.parse_args()

host = parsed_args.host
username = parsed_args.username
password = parsed_args.password
license_key = parsed_args.licensekey
hostname = parsed_args.hostname
ntpserver = parsed_args.ntpserver
vpn = {}
vpn['local-self-ip'] = parsed_args.localselfip
vpn['local-public-ip'] = parsed_args.localpublicip
vpn['remote-public-ip'] = parsed_args.remotepublicip
vpn['pre-shared-key'] = parsed_args.presharedkey
vpn['tunnel-source-network'] = parsed_args.tunnelsourcenet
vpn['tunnel-destination-network'] = parsed_args.tunneldestinationnet
vpn['tunnel-name'] = 'ipsec_peer-' + vpn['remote-public-ip']
vpn['tunnel-self-ip'] = parsed_args.tunnelselfiplocal

# License the VE

if license_key is not None:
    print('Licensing ' + host + ' with key ' + license_key)
    apiCallResponse = icontrol_post(host,username,password,'/mgmt/tm/sys/license',{"command":"install","registrationKey":license_key})
    if 'New license installed' in apiCallResponse:
        print('License installed successfully.')
    else:
        print('Error! ' + apiCallResponse)
        quit()
else:
    print("License key not specified - skipping licensing")

# Disable the GUI setup wizard since we're configuring via REST

print('Disabling the GUI Setup Wizard')
apiCallResponse = icontrol_patch(host,username,password,'/mgmt/tm/sys/global-settings',{"guiSetup":"disabled"})
if '"kind":"tm:sys:global-settings:global-settingsstate"' and '"guiSetup":"disabled"' in apiCallResponse:
    print('Success!')
else:
    print('Error! ' + apiCallResponse)
    quit()

# Set the hostname if specified

if hostname is not None:
    print('Setting the hostname to ' + hostname + ' on ' + host)
    apiCallResponse = icontrol_patch(host, username, password, '/mgmt/tm/sys/global-settings',{"hostname":hostname})
    if '"kind":"tm:sys:global-settings:global-settingsstate"' and '"hostname":"' + hostname + '"' in apiCallResponse:
        print('Success!')
    else:
        print('Error! ' + apiCallResponse)
        quit()
else:
    print('Hostname not specified - skipping hostname configuration')

# Set the NTP server if specified

if ntpserver is not None:
    print('Adding NTP server ' + ntpserver + ' to ' + host)
    apiCallResponse = icontrol_patch(host,username,password,'/mgmt/tm/sys/ntp',{"servers":[ntpserver]})
    if '"kind":"tm:sys:ntp:ntpstate"' in apiCallResponse:
        print('Success!')
    else:
        print('Error! ' + apiCallResponse)
        quit()
else:
    print('NTP server not specified - skipping NTP server configuration')

#
# Begin IPSec tunnel configuration steps
#

# Create the IPSec policy

print('Creating the IPSec Policy (' + vpn['tunnel-name'] + ')')
apiPayload = {}
apiPayload['name'] = vpn['tunnel-name']
apiPayload['ikePhase2AuthAlgorithm'] = 'sha256'
apiPayload['ikePhase2EncryptAlgorithm'] = 'aes256'
apiPayload['ikePhase2PerfectForwardSecrecy'] = 'modp1024'
apiPayload['ikePhase2Lifetime'] = 1440
apiPayload['ikePhase2LifetimeKilobytes'] = 0
apiPayload['mode'] = 'interface'
apiPayload['protocol'] = 'esp'
apiPayload['ipcomp'] = 'none'
apiPayload['partition'] = 'Common'
apiCallResponse = icontrol_post(host,username,password,'/mgmt/tm/net/ipsec/ipsec-policy',apiPayload)
if '"kind":"tm:net:ipsec:ipsec-policy:ipsec-policystate"' in apiCallResponse :
    print('Success!')
else:
    print('Error! ' + apiCallResponse)
    quit()

# Create the IPSec traffic selector

print('Creating the IPSec traffic selector (' + vpn['tunnel-name'] + ')')
apiPayload = {}
apiPayload['name'] = vpn['tunnel-name']
apiPayload['partition'] = 'Common'
apiPayload['action'] = 'protect'
apiPayload['sourceAddress'] = vpn['tunnel-source-network']
apiPayload['sourcePort'] = 0
apiPayload['destinationAddress'] = vpn['tunnel-destination-network']
apiPayload['destinationPort'] = 0
apiPayload['direction'] = 'both'
apiPayload['ipProtocol'] = 255
apiPayload['ipsecPolicy'] = vpn['tunnel-name']
apiPayload['order'] = 0

apiCallResponse = icontrol_post(host,username,password,'/mgmt/tm/net/ipsec/traffic-selector',apiPayload)
if '"kind":"tm:net:ipsec:traffic-selector:traffic-selectorstate"' in apiCallResponse:
    print('Success!')
else:
    print('Error! ' + apiCallResponse)
    quit()

# Set the default IPSec traffic selector to high order

print('Setting the default IPSec traffic selector to order 100')
apiPayload = {}
apiPayload['order'] = 100
apiCallResponse = icontrol_patch(host,username,password,'/mgmt/tm/net/ipsec/traffic-selector/default-traffic-selector-interface',apiPayload)
if '"kind":"tm:net:ipsec:traffic-selector:traffic-selectorstate"' in apiCallResponse:
    print('Success!')
else:
    print('Error! ' + apiCallResponse)
    quit()

# Create the IKE peer

print('Creating the IKE peer (' + vpn['tunnel-name'] + ')')
apiPayload = {}
apiPayload['name'] = vpn['tunnel-name']
apiPayload['myIdType'] = 'address'
apiPayload['myIdValue'] = vpn['local-public-ip']
apiPayload['peersIdType'] = 'address'
apiPayload['peersIdValue'] = vpn['remote-public-ip']
apiPayload['phase1AuthMethod'] = 'pre-shared-key'
apiPayload['phase1EncryptAlgorithm'] = 'aes256'
apiPayload['phase1HashAlgorithm'] = 'sha256'
apiPayload['phase1PerfectForwardSecrecy'] = 'modp1024'
apiPayload['prf'] = 'sha256'
apiPayload['presharedKey'] = vpn['pre-shared-key']
apiPayload['remoteAddress'] = vpn['remote-public-ip']
apiPayload['version'] = ['v2']
apiPayload['dpdDelay'] = 30
apiPayload['lifetime'] = 1440
apiPayload['mode'] = 'main'
apiPayload['natTraversal'] = 'off'
apiPayload['passive'] = 'false'
apiPayload['generatePolicy'] = 'off'
apiPayload['trafficSelector'] = [vpn['tunnel-name']]
apiCallResponse = icontrol_post(host,username,password,'/mgmt/tm/net/ipsec/ike-peer',apiPayload)
if '"kind":"tm:net:ipsec:ike-peer:ike-peerstate"' in apiCallResponse:
    print('Success!')
else:
    print('Error! ' + apiCallResponse)
    quit()

# Create the tunnel profile

print('Creating the tunnel profile (' + vpn['tunnel-name'] + ')')
apiPayload = {}
apiPayload['name'] = vpn['tunnel-name']
apiPayload['defaultsFrom'] = '/Common/ipsec'
apiPayload['trafficSelector'] = vpn['tunnel-name']

apiCallResponse = icontrol_post(host,username,password,'/mgmt/tm/net/tunnels/ipsec',apiPayload)
if '"kind":"tm:net:tunnels:ipsec:ipsecstate"' in apiCallResponse:
    print('Success!')
else:
    print('Error! ' + apiCallResponse)
    quit()

# Create the tunnel object

print('Creating the tunnel object (' + vpn['tunnel-name'] + ')')
apiPayload = {}
apiPayload['name'] = vpn['tunnel-name']
apiPayload['autoLasthop'] = 'default'
apiPayload['idleTimeout'] = 300
apiPayload['key'] = 0
apiPayload['localAddress'] = vpn['local-self-ip']
apiPayload['mode'] = 'bidirectional'
apiPayload['mtu'] = 0
apiPayload['profile'] = vpn['tunnel-name']
apiPayload['remoteAddress'] = vpn['remote-public-ip']
apiPayload['tos'] = 'preserve'
apiPayload['transparent'] = 'disabled'
apiPayload['usePmtu'] = 'enabled'
apiCallResponse = icontrol_post(host,username,password,'/mgmt/tm/net/tunnels/tunnel',apiPayload)
if '"kind":"tm:net:tunnels:tunnel:tunnelstate"' in apiCallResponse:
    print('Success!')
else:
    print('Error! ' + apiCallResponse)
    quit()

# Create the self-IP for the tunnel-route

print('Creating the local tunnel interface self-IP (' + vpn['tunnel-name'] + ')')
apiPayload = {}
apiPayload['name'] = vpn['tunnel-name']
apiPayload['address'] = vpn['tunnel-self-ip']
apiPayload['vlan'] = vpn['tunnel-name']
apiPayload['traffic-group'] = 'traffic-group-local-only'
apiPayload['allowService'] = 'all'
apiCallResponse = icontrol_post(host,username,password,'/mgmt/tm/net/self',apiPayload)
if '"kind":"tm:net:self:selfstate"' in apiCallResponse:
    print('Success!')
else:
    print('Error! ' + apiCallResponse)
    quit()

# Create the static route for tunneling

print('Creating the static route (' + vpn['tunnel-name'] + ')')
apiPayload = {}
apiPayload['name'] = vpn['tunnel-name']
apiPayload['tmInterface'] = vpn['tunnel-name']
apiPayload['network'] = vpn['tunnel-destination-network']
apiPayload['mtu'] = 0
apiCallResponse = icontrol_post(host,username,password,'/mgmt/tm/net/route',apiPayload)
if '"kind":"tm:net:route:routestate"' in apiCallResponse:
    print('Success!')
else:
    print('Error! ' + apiCallResponse)
    quit()

# Create the default IP forwarding virtual server

print('Creating the default IP forwarding virtual server')
apiPayload = {}
apiPayload['name'] = 'ip_forwarding_vs'
apiPayload['destination'] = '/Common/0.0.0.0:0'
apiPayload['ipProtocol'] = 'any'
apiPayload['mask'] = '0.0.0.0'
apiPayload['source'] = '0.0.0.0/0'
apiPayload['sourceAddressTranslation'] = {'type':'none'}
apiPayload['sourcePort'] = 'preserve'
apiPayload['profiles'] = ['/Common/fastL4']
apiPayload['enabled'] = True
apiPayload['translateAddress'] = 'disabled'
apiPayload['translatePort'] = 'disabled'
apiCallResponse = icontrol_post(host,username,password,'/mgmt/tm/ltm/virtual',apiPayload)
if '"kind":"tm:ltm:virtual:virtualstate"' in apiCallResponse:
    print('Success!')
else:
    print('Error! ' + apiCallResponse)
    quit()

# Save the configuration

print('Saving the configuration')
apiPayload = {}
apiPayload['command'] = 'save'
apiCallResponse = icontrol_post(host,username,password,'/mgmt/tm/sys/config',apiPayload)
if '"kind":"tm:sys:config:savestate","command":"save"' in apiCallResponse:
    print('Success!')
else:
    print('Error! ' + apiCallResponse)
    quit()
