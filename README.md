# MotoMoca1025

mm1025.py:

Usage: ./mm1025.py -d \<IP\> 

Script to get config and status information from Motorola MoCa MM1025 adapters.

Outputs text most of the status and device info, but no PHY/rate data, or band/band mask info. 

Optional to set device IP, username and password in script, or provide via CLI arguments, If any are not provided via script or cli it will prompt.

Easy to change the output info.

Script does not allow updating/changing of any configuration/settings. Though it should be doable with modification and adding using http puts. 

Default username preset as admin (default and not user changeable with firmware version 1.18.2.2.)

Provided with very limited testing. No warranty. Use at your own risk. Not responsible for anything. This is not good code, but it works for me.  
