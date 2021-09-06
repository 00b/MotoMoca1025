#!/usr/bin/python3
import requests
import sys
import smtplib
import argparse
import pathlib
import urllib3,json
import getpass
'''
Script to extract status and operational data from Motrola MM1025 MOCA Adapters

'''
#default username and device IP.
username = 'admin'
devicehost = '169.254.1.1' # update if you chage the IP to be on your regular network (192.168.0.X?)
password = '' # add password if you want


#argument parsing/setup. 
parser = argparse.ArgumentParser()
parser.add_argument("--username", "-u", help="username to use")
parser.add_argument("--password", "-p", help="password to use")
parser.add_argument("--ip", "-d", help="ip address of MM1025")
args = parser.parse_args()

#if arguments specified use them. 
if args.username:
    username=args.username
if args.password:
    password=args.password
if args.ip:
    devicehost=args.ip

#prompt for device addres:
if len(devicehost) == 0:
    devicehost =input("Device IP: ")

#prompt for username if none entered:
if len(username) == 0:
    username=input("Username: ")
else:
    print ("using username: "+username)

#prompt for password if none entered: 
if len(password) == 0:
    password = getpass.getpass()
else:
    print ('using provided password')

#Request name to path. 
reqdict={'AdapterName':'/ms/1/0x212/GET','BeaconPower':'/ms/0/0x100e/GET','ChipID':'/ms/1/0x303/GET','EncdPrivMode':'/ms/0/0x130D/GET',
        'EncdPrivPassGet':'/ms/0/0x1400/GET','FrameInfo':'/ms/0/0x14','IPAddr':'/ms/1/0x20b/GET','LocalInfo':'/ms/0/0x15','NetMask':'/ms/1/0x210/GET',
        'Gateway':'/ms/1/0x211/GET','NetInfo':'/ms/0/0x16','NwSearch':'/ms/0/0x1001/GET','MiscPhy':'/ms/0/0x24',
        'M25phyinfo':'/ms/0/0x7f','TXPower':'/ms/0/0x10a8/GET','PrefNC':'/ms/0/0x1002/GET'}

#Setup some baseline requests vars.
#Some of these change in a couple requests but those are handled in the functions.
contenttype = 'application/x-www-form-urlencoded'
payload = {"data":[]}
headers = {'Content-type': 'application/x-www-form-urlencoded','Accept': 'text/html, */*'}
baseurl = 'http://'+devicehost

#Get some info right away, some of the other calls will refrence this baseline device info.  
url = 'http://'+devicehost+reqdict['LocalInfo']
DevReq = requests.post(url,verify=False, data=payload, headers=headers, auth=(username,password))

if DevReq.ok:
    #print ('OK!')
    devdata = json.loads(DevReq.content)
else:
    print ('Got status code : ' + str(DevReq.status_code))
    print ('Failed to make request. bad password?')
    print (DevReq.reason)
    exit(1)

#print (json.dumps(devdata, indent=2))


def AdapterName():
    #print('AdapterName')
    requrl = baseurl+reqdict['AdapterName'] 
    RoomNames = ["Master","LivingRoom","TVRoom","GameRoom","Office","Den","Room1","Room2","Room3","Room4","Room5","Kids1","Kids2","Bedroom1","Bedroom2","Office1","Office2"]
    rawdata = requests.post(requrl, verify=False, auth=(username,password))
    namedata = json.loads(rawdata.content)
    return(RoomNames[int(namedata['data'][0],0)])

def SocInfo():
    Chips= ("MXL370x", "MXL371x", "UNKNOWN");
    requrl = baseurl+reqdict['ChipID']
    ChipResp = requests.post(requrl, verify=False, auth=(username,password))
    ChipInfo = json.loads(ChipResp.content)
    ChipID = int(ChipInfo['data'][0],16)-0x15
    ''' this its done in JS on the device. 
    var socVersion = '';
    var retVal;
    var i = 0;
    do
    {
        retVal = byte2ascii(localInfoVal[21+i].slice(2,10));
        socVersion  += retVal;
        i++;
    } while (retVal);
    '''
    #But I'm just gonna go smash the bytes to together and trim the 00s 
    SoCVerHi=devdata['data'][21][2:]
    SoCVerLo=devdata['data'][22][2:]
    SoCVer = str(bytes.fromhex(SoCVerHi),'utf-8')+str(bytes.fromhex(SoCVerLo),'utf-8')
    SoCVer = SoCVer.rstrip('\x00')
    return({'SoCChip':Chips[ChipID],'SoCVer': SoCVer})

def MocaInfo():
    ''' JS way from device to get the nework moca version. 
    var nwMocaVer = parseInt(cutS(localInfoVal[11]), 16);
    nwMocaVerVal = (nwMocaVer>>4&0xf)+"."+((nwMocaVer>>0)&0xf);
    '''
    NwMocaVer = devdata['data'][11]
    NwMocaVerString = str(NwMocaVer[8::2])+'.'+str(NwMocaVer[9::1])
    ''' JS way from device interface to get myMocaVer.
    var myMocaVer = parseInt(cutS(netInfoVal[4]), 16);
    myMocaVerVal = (myMocaVer>>4&0xf)+"."+((myMocaVer>>0)&0xf);
    '''
    requrl=baseurl+reqdict['NetInfo']
    netpayload = "{\"data\":[0]}"
    NetRaw = requests.post(requrl, headers=headers, data=netpayload, verify=False, auth=(username,password))
    NetInfo = json.loads(NetRaw.content)
    MyMocaVer = NetInfo['data'][4]
    MyMocaVerString = str(MyMocaVer[8::2])+'.'+str(MyMocaVer[9::1])   
    #Get Beacon Channel
    requrl=baseurl+reqdict['MiscPhy']
    Phyresp = requests.post(requrl, headers=headers, data=payload, verify=False, auth=(username,password))
    PhyJSON = json.loads(Phyresp.content)
    BeaconHex=PhyJSON['data'][1][2:]
    BeaconCh=int(BeaconHex,16)
    #Channels
    requrl=baseurl+reqdict['M25phyinfo']
    Chanresp = requests.post(requrl, headers=headers, data=payload, verify=False, auth=(username,password))
    ChanJSON = json.loads(Chanresp.content)
    PriChanOffSet=int(devdata['data'][18][2:],16)
    SecChanOffSet=int(devdata['data'][19][2:],16)
    CustomBands=int(devdata['data'][28][2:],16)
    if PriChanOffSet == 0:
        PriChan = BeaconCh
    elif PriChanOffSet == 1:
        PriChan = BeaconCh + 25
    elif PriChanOffset == 2:
        PriChan = BeaconCh -25
    if SecChanOffSet == 1:
        if CustomBands == 1:
            SecChan = PriChan - 125
        else:
            SecChan = PriChan - 100
    elif SecChanOffSet == 2:
        if CustomBands == 1:
            SecChan = PriChan + 125
        else:
            SecChan = PriChan + 100

    if SocInfo()['SoCChip'] == 'MXL370x':
        FirstChan = 'N/A'
        NumChan = 'N/A'
    else:
        FirstChan = int(ChanJSON['data'][2][2:],16)
        NumChan = int(ChanJSON['data'][3][2:],16)
    return({'NetworkMocaVer':NwMocaVerString,'MyMocaVer':MyMocaVerString,'BeaconChan':BeaconCh,'PrimaryChan':PriChan,'SecChan':SecChan,'FirstChan':FirstChan,'NumChans':NumChan})


def FeatStatus(FeatItem):
    requrl=baseurl+reqdict[FeatItem]
    rawdata=requests.post(requrl, verify=False, auth=(username,password))
    data=json.loads(rawdata.content)
    if int(data['data'][0],16) == 1:
        return(True)
    if int(data['data'][0],16) == 0:
        return(False)

def LinkStatus():
    req = '/ms/0/0x15'
    requrl ='http://'+ devicehost + req
    rawdata = requests.post(requrl, verify=False, data=payload, auth=(username,password))
    linkdata = json.loads(rawdata.content)
    if (int(linkdata['data'][5],0)) == 1:
        return('Up')
    else:
        return('Down')

def PowerLvls():
    requrl=baseurl+reqdict['TXPower']
    TxPwrraw=requests.post(requrl, verify=False, auth=(username,password))
    TxPwrJ = json.loads(TxPwrraw.content)
    TxPwr = int(TxPwrJ['data'][0],16)
    requrl=baseurl+reqdict['BeaconPower']
    BcnPwrraw=requests.post(requrl, verify=False, auth=(username,password))
    BcnPwrJ=json.loads(BcnPwrraw.content)
    BcnPwr=int(BcnPwrJ['data'][0],16)
    return({'TXPower':TxPwr,'BeaconPower':BcnPwr})

def SecInfo():
    requrl = baseurl+reqdict['EncdPrivMode']
    resp = requests.post(requrl, verify=False, auth=(username,password))
    PrivMode=json.loads(resp.content)
    if PrivMode['data'][0]=='0x00000007':
        PrivModeTxt = 'Enhanced Privacy Enabled'
    else:
        PrivModeTxt = 'Enhanced Privacy Disabled'
    requrl = baseurl+reqdict['EncdPrivPassGet']
    data = requests.post(requrl, verify=False, auth=(username,password))
    passdata = json.loads(data.content)
    secpass=''
    for x in passdata['data']:
        #print(x[2:])
        hexstring=x[2:]
        bytestring=bytes.fromhex(hexstring)
        textout=bytestring.decode('utf-8')
        #print(textout)
        secpass=secpass+textout 
    secpass=secpass.rstrip('\x00')
    bands = {"D-Ext","D-Low","D-High","E","F-SAT","F-CBL","H","Custom"}
    return({'PrivacyMode':PrivMode['data'][0],'EnhancedPrivacyPassword':secpass,'PrivacyModeDesc':PrivModeTxt})

def NodeInfo():
    NodeID =int(devdata['data'][0][2:],16)
    return({'NodeID':NodeID})

def PhyRates(): 
    print('maybe never')
    '''
        <form name="fmrInfo" method="post" action="/ms/0/0x1D">
        <input type="hidden" name="data" value="" disabled="true" />
        <input type="hidden" name="data2" value="" disabled="true" />)
    
        ***sooo this thing looks to be extra tricky. 
        The MM1025 JS somehow polls other nodes for their data. 
        Also not shown here lots more math based on Moca Version
        Also a lot of data extraction from lots of fields which are less than clear to me.  

        From the JS on device: 
        /* Send MOCA shell command to the node */
        document.fmrInfo.data.value = currNodeMask;
        document.fmrInfo.data2.value = (finalVer);
        doFormGetMultipleDataJSON(document.fmrInfo,   "phyRates.html",function(data, nu) {fmrInfo[node_id] = data.data; formLoad(node_id + 1);}, function(data) {}, node_id);
      }

    '''
    statuspath = '/ms/0/0x1D'

    contenttype = 'application/x-www-form-urlencoded'
    payload = "{\"data\":[1,2]}"
    headers = {'Content-type': 'application/x-www-form-urlencoded','Accept': 'text/html, */*'}
    url = 'http://'+devicehost+statuspath
    #print ('Requesting : ' + url)
    #print (payload)
    page = requests.post(url,verify=False, data=payload, headers=headers, auth=(username,password))
    #print(page)
    #print(page.content)
    fmrInfo=json.loads(page.content)
    print(json.dumps(fmrInfo,indent=2))
    
    for Node in range(16):
        print(Node)
        #getMocaVerfor nodes
    
    #print (fmrInfo)
    #print (fmrInfo.content)

def Gpio():
    #NO idea what this indicates but it shows up in the UI so here it is. 
    reqpath = '/ms/1/0xb17'
    requrl = baseurl+reqpath
    gpioresp = requests.post(requrl, verify=False, data=payload, auth=(username,password))
    gpiojson = json.loads(gpioresp.content)
    return(gpiojson['data'][0])

def Netinfo():
    req = '/ms/1/0x20b/GET'
    requrl = 'http://'+devicehost + req
    iprawdata = requests.post(requrl, verify=False, auth=(username,password))
    ipdata = json.loads(iprawdata.content)
    ipinhex = ipdata['data'][0][2:]
    ipaddr = "%i.%i.%i.%i" % (int(ipinhex[0:2],16),int(ipinhex[2:4],16),int(ipinhex[4:6],16),int(ipinhex[6:8],16))
   
    reqmac = '/ms/1/0x103/GET'
    requrl = 'http://'+devicehost + reqmac
    macraw = requests.post(requrl, verify=False, auth=(username,password))
    macdata = json.loads(macraw.content)
    machi = macdata['data'][0][2:]
    maclo = macdata['data'][1][2:6]
    mac = machi+maclo
    macfmt = ':'.join(map('{}{}'.format, *(mac[::2], mac[1::2]))) 
   
    requrl = baseurl+reqdict['NetMask']
    NetMaskresp = requests.post(requrl, verify=False, auth=(username,password))
    NetMaskdata=json.loads(NetMaskresp.content)
    NetMaskHex = NetMaskdata['data'][0][2:]
    NetMask =  "%i.%i.%i.%i" % (int(NetMaskHex[0:2],16),int(NetMaskHex[2:4],16),int(NetMaskHex[4:6],16),int(NetMaskHex[6:8],16))
   
    requrl = baseurl+reqdict['Gateway'] 
    Gwresp = requests.post(requrl, verify=False, auth=(username,password))
    GwData = json.loads(Gwresp.content)
    GwHex = GwData['data'][0][2:]
    GwIP =  "%i.%i.%i.%i" % (int(GwHex[0:2],16),int(GwHex[2:4],16),int(GwHex[4:6],16),int(GwHex[6:8],16))
    
    return({'IP':ipaddr,'NetMask':NetMask,'Gateway':GwIP,'MAC':macfmt})
    '''
    How is done in JS
    function hex2mac(hi, lo)
    {
    var mac = n2s(hi>>24&0xff,16)+":"+n2s((hi>>16)&0xff,16)+":"+n2s((hi>>8)&0xff,16)+":"+n2s(hi&0xff,16)+":"+n2s(lo>>24&0xff,16)+":"+n2s((lo>>16)&0xff,16);
    return mac;
    } 
    LOOKs like it just reads off 2 bytes and different off sets. from hi at 24,16,8,0 then the low at 24 and 16. 
    '''
def MocaNC():
    return(str(int(devdata['data'][1][2:],16)))

def EthStats():
    #Ethernet statistics. 
    '''
    // From frameInfo
    txgood = ((parseInt(cutS(frameInfoVal[12]), 16)&0xffffffff)*4294967296)+parseInt(cutS(frameInfoVal[13]), 16);
    txbad = ((parseInt(cutS(frameInfoVal[30]), 16)&0xffffffff)*4294967296)+parseInt(cutS(frameInfoVal[31]), 16);
    txdropped = ((parseInt(cutS(frameInfoVal[48]), 16)&0xffffffff)*4294967296)+parseInt(cutS(frameInfoVal[49]), 16);
    ethTxVal = "Tx Good:&nbsp;"+txgood+"<br />Tx Bad:&nbsp;"+txbad+"<br />Tx Dropped:&nbsp;"+txdropped;

    rxgood = ((parseInt(cutS(frameInfoVal[66]), 16)&0xffffffff)*4294967296)+parseInt(cutS(frameInfoVal[67]), 16);
    rxbad = ((parseInt(cutS(frameInfoVal[84]), 16)&0xffffffff)*4294967296)+parseInt(cutS(frameInfoVal[85]), 16);
    rxdropped = ((parseInt(cutS(frameInfoVal[102]), 16)&0xffffffff)*4294967296)+parseInt(cutS(frameInfoVal[103]), 16);
    ethRxVal = "Rx Good:&nbsp;"+rxgood+"<br />Rx Bad:&nbsp;"+rxbad+"<br />Rx Dropped:&nbsp;"+rxdropped;
    '''
    reqpayload = "{\"data\":[0]}"
    requrl = baseurl + reqdict['FrameInfo']
    FrameResp = requests.post(requrl, verify=False, data=reqpayload, auth=(username,password))
    FrameData = json.loads(FrameResp.content)
    TxGood = int(FrameData['data'][12][2:],16) *4294967296 + int(FrameData['data'][13][2:],16)
    TxBad  = int(FrameData['data'][30][2:],16) *4294967296 + int(FrameData['data'][31][2:],16)
    TxDrop = int(FrameData['data'][48][2:],16) *4294967296 + int(FrameData['data'][39][2:],16)
    RxGood = int(FrameData['data'][66][2:],16) *4294967296 + int(FrameData['data'][67][2:],16)
    RxBad  = int(FrameData['data'][84][2:],16) *4294967296 + int(FrameData['data'][85][2:],16)
    RxDrop = int(FrameData['data'][102][2:],16) *4294967296 + int(FrameData['data'][103][2:],16)
    return({'TxGood':TxGood,'TxBad':TxBad,'TxDropped':TxDrop,'RxGood':RxGood,'RxBad':RxBad,'RxDropped':RxDrop})


IPMAC=(Netinfo())
print ('IP Address  : ' + IPMAC['IP'])
print ('Net Maek    : ' + IPMAC['NetMask'])
print ('Gateway     : ' + IPMAC['Gateway'])
print ('MAC Address : ' + IPMAC['MAC'])
print ('-----------------------------')
print ('AdapterName : ' + AdapterName())
print ('Node ID     : ' + str(NodeInfo()['NodeID']))
print ('Link Status : ' + LinkStatus())
print ('Network Search : ' + str(FeatStatus('NwSearch')))
print ('Prefered Network Coordinator : ' + str(FeatStatus('PrefNC')))
print ('Network Coordinator Node : ' + MocaNC())
if str(MocaNC()) == str(NodeInfo()['NodeID']):
    print ('Is Network Coordinator : True')
else:
    print ('Is Network Coordinator : False') 
Moca = MocaInfo()
print ('MoCa Net Ver: ' + Moca['NetworkMocaVer'])
print ('MyMoCa Ver  : ' + Moca['MyMocaVer'])
print ('Beacon Ch   : ' + str(Moca['BeaconChan']))
print ('Primary Ch  : ' + str(Moca['PrimaryChan']))
print ('Secondary Ch: ' + str(Moca['SecChan']))
print ('Frist Ch    : ' + str(Moca['FirstChan']))
print ('Number of Ch: ' + str(Moca['NumChans']))
Lvl= PowerLvls()
print ('Beacon Power: ' + str(Lvl['BeaconPower']) + ' (1-10)')
print ('Tx Power    : ' + str(Lvl['TXPower']) + ' (1-10)') 
print ('GPIO        : ' + Gpio())
#LinkStatus()
print ('-----------------------------')
SoC=(SocInfo())
print ('SoC Model  : ' + SoC['SoCChip'])
print ('Soc Verion : ' + SoC['SoCVer'])


print ('-----------------------------')
EthFrames = EthStats()
print ('EtherNet Stats')
print ('Tx Good   : ' + str(EthFrames['TxGood']))
print ('Tx Bad    : ' + str(EthFrames['TxBad']))
print ('Tx Dropped: ' + str(EthFrames['TxDropped']))
print ('Rx Good   : ' + str(EthFrames['RxGood']))
print ('Rx Bad    : ' + str(EthFrames['RxBad']))
print ('Rs Dropped: ' + str(EthFrames['RxDropped']))

print ('------------------------------')
SecuirtyInfo = SecInfo()
print ('Privacy Mode : ' + SecuirtyInfo['PrivacyMode'])
print ('Enhanced Privacy : ' + SecuirtyInfo['PrivacyModeDesc'])
print ('Enhacned Privacy Password : ' + SecuirtyInfo['EnhancedPrivacyPassword']) 
