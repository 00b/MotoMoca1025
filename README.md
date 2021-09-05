# MotoMoca1025

mm1025.py:

Usage: ./mm1025.py -d \<IP\> 

Outputs text of most of the status and device info, but no PHY/rate data.  

Script to get config and status information from Motorola MoCa MM1025 adapters.

Optional to set device IP, username and password in script, or provide via CLI arguments. If uersname/password not provided it will prompt.

Easy to change the output info or switch any outputs to JSON as the functions return JSON. 

Script does not allow updating/changing of any configuration/settings. Though it should be possible.

Default username preset as admin (default and not user changeable with firmware version 1.18.2.2.)

Provided with limited testing. No warranty. Use at your own risk. 
