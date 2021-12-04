import pyshark
#import os
capture = pyshark.LiveCapture(interface='Wi-Fi' , display_filter="ntp")
capture.sniff(timeout=60)
if len(capture) != 0 :
    print("Suspected NTP attack")
    #print(disabling WiFi)
    #os.system("netsh interface set interface 'Wifi' disabled")
    #print("Wifi Disabled")
else:
    print("No possiblity of NTP attack currently")
