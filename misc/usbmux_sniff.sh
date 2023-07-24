#!/bin/sh
sudo mv /var/run/usbmuxd /var/run/usbmux_real
sudo socat -t100 -x -v UNIX-LISTEN:/var/run/usbmuxd,mode=777,reuseaddr,fork UNIX-CONNECT:/var/run/usbmux_real
sudo mv /var/run/usbmux_real /var/run/usbmuxd
