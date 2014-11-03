Roaming Monkey
==============

This application is an add-on for Asterisk. It interacts with a set of Asterisk servers by connecting to their Asterisk Manager Interfaces (AMIs) and monitor SIP clients for disconnection events. If a configured SIP client disconnects forecefully, the tool will attempt to redirect the channel(s) the client was talking with, to a specific context in the Dialplan. The main purpose for this tool is to redirect dropped calls in a WiFi connected mobile SIP client (Android/iOS/BB/etc.) to the cell number of that same phone, providing basic WiFI/VoIP to PSTN roaming.

*This application was developed for Asterisk 1.6, using Ubuntu 10.04 LTS and the packages available in that distribution's repositories. There isn't any support for other Asterisk versions or Linux distributions.*

**Contributions and pull requests are welcome :-)**



# Manual installation instructions
```
1. Drop the contents of this directory in /opt/monkey
2. Make sure ownership of all the items and the directory itself is root:root
3. Symlink monkey-init-script to /etc/init.d/monkey
4. Copy monkey.conf.example to /etc/monkey.conf and modify it to match your
   Asterisk server
   NOTE: For this tool to communicate with Asterisk an AMI user hast to be set
   up. There is an example file manager.d.monkey.conf.example that can be used
   by copying it to /etc/asterisk/manager.d/monkey.conf.
5. Start the daemon by calling /etc/init.d/monkey start, or
   /sbin/service monkey start, or whatever your distribution of choice
   recommends
6. Profit
```
