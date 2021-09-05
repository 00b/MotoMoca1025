# MotoMoca1025
Script to get config and status information from Motorola MoCa MM1025 adapters.

Outputs text of most of the status and device info. No PHY data. 

Would be very easy to chang the output info or switch any outputs to JSON as the functions return JSON. 

Optional to set device IP,username and password in script, otherwise provide via CLI arguments. 

Usage: ./mm1025.py -d \<IP\> -u \<UserName\> -p \<Password\>
