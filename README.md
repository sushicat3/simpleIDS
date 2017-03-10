# simpleIDS
Simple Intrusion Detection System for Port Scans

Port scanning will normally precede an attack. IP's that are port scanning will have many more SYN packets sent than SYNACK packets recieved. This behavior could indicate an attacker. 

This simple IDS detects port scans by flagging IPs with three times as many SYNS as SYNACK packets.
