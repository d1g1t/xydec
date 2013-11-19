
 xydec
=======

  Run on a pcap (not pcap-ng) dump of Pokémon X/Y traffic.  Outputs formatted
  output (using SGR sequences); make sure you use a relatively modern terminal.

    make
    ./xydec <dump.pcap | less -r


 to use like instacheck
-----
I've slightly modified it to show some of the info that [instacheck](http://www.smogon.com/forums/threads/instacheck-hotspot-a-fast-pok%C3%A9mon-checker-for-xy.3492531/) shows. Original code is intact and simply commented out.
I haven't coded in C in a really long time and my edits may be rubbish.
You can get it to show other relevant info such as moves/egg moves etc by editing xydec.c

 my setup
-----
I am using a raspberry-pi with a usb wifi stick [acting as a router](http://elinux.org/RPI-Wireless-Hotspot) and capturing the packets with

    dumpcap -i wlan0 -P -w - | /home/d1g1t/shinyvaluedetect/xydec

 thanks
-----
FireyFly for xydec
OmegaDonut for instacheck (pokemon/nature/etc names are taken from there along with the block permutations)
