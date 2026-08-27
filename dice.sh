#!/bin/bash
case $1 in 12)e=32;c=1;;24)e=64;c=2;;esac
h=$(printf %s "$2"|sha256sum|cut -c1-$e)
h+=$(xxd -r -p<<<"$h"|sha256sum|cut -c1-$c)
BC_LINE_LENGTH=0 bc<<<"obase=2048;ibase=16;1${h^^}"|xargs -n1|sed -e 1d -f "${0%/*}/bip39-bc2048.sed"|paste -sd' '
