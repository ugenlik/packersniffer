

Author:

Umut Can Genlik


How to Run the program :

If user is on a Mac OSX machine, user should use terminal and  "su" comment to run program as admin otherwise program will not compile correctly. Default Ethernet Device name for a mac is "en1", if user want to run code on a Linux machine, user should change name to its Network Device.


What program does: 
A packet sniffer can view a wide variety of information that is being transmitted over the network as well as the network it is linked to. Packet sniffers exist in the form of software or hardware and can capture network traffic that is both inbound and outbound and monitor password use and user names along with other sensitive information. A packet sniffer allows you to set the interface of the network to view all of the information that is transmitted over the network. When the data passes through the system, it is captured and stored in memory so the information can be analyzed.

The packet sniffer gets its name from normal computer usage where the individual computer inspects packets of data that match the address of the computer. However, with a packet sniffer, it can examine all of the data from all of the computers that are connected to the network by viewing every packet that is sent over the network. A packet sniffer that has been installed on the network is capable of examining all of your email contacts, email messages, downloaded files, Web sites you visited, and all of your audio and video activity.

Instructions :

Compile witth
gcc -Wall -pedantic ugenlik1.c -lpcap (-o foo_err_something) 
a.out (# of packets) "filter string"

Example terminal commands should be like following

sh-3.2# gcc -Wall -pedantic ugenlik1.c -lpcap -o umut
ugenlik1.c:29:20: warning: C++ style comments are not allowed in ISO C90
ugenlik1.c:29:20: warning: (this will be reported only once per input file)
sh-3.2# ./umut 8
Write a file name with extension : log.txt
========================================================
ETH: Source: e0:2a:82:51:60:d8 
Destination: 33:33:0:1:0:2 
Type = (others)
  Length 150
ETH: Source: 0:25:d3:e5:0:a2 
Destination: ff:ff:ff:ff:ff:ff 
Type = (ARP)
  Length 42
ETH: Source: e0:2a:82:51:60:d8 
Destination: 33:33:0:1:0:2 
Type = (others)
  Length 150
ETH: Source: e0:2a:82:51:60:d8 
Destination: 33:33:0:1:0:2 
Type = (others)
  Length 150
ETH: Source: 0:25:d3:e5:0:a2 
Destination: ff:ff:ff:ff:ff:ff 
Type = (ARP)
  Length 42
ETH: Source: 78:dd:8:c4:8f:a8 
Destination: 1:0:5e:7f:ff:fa 
Type = (IP)
  Length 478
IP: Source 192.168.34.108: Destination 27655->192.168.34.108:27655
 Type of Service: 0 Length of Ip Header : 464
 Fragment offset Field :0
 Time to live: 1
 Protocol: 17
 Checksum: 38111
 Sequence Number: 250402624311125047516
 Nack Sequence: 270611365012425044040
Window: 44012
========================================================
ETH: Source: 78:dd:8:c4:8f:a8 
Destination: 33:33:0:0:0:c 
Type = (others)
  Length 505
ETH: Source: 78:dd:8:c4:8f:a8 
Destination: 1:0:5e:7f:ff:fa 
Type = (IP)
  Length 558
IP: Source 192.168.34.108: Destination 27655->192.168.34.108:27655
 Type of Service: 0 Length of Ip Header : 544
 Fragment offset Field :0
 Time to live: 1
 Protocol: 17
 Checksum: 17375
 Sequence Number: 250402624311125047516
 Nack Sequence: 270611365012425044040
Window: 44012
========================================================

finished