#!/usr/bin/env python3
from pwn import *
import sys, os

# pwntools RE/exploit template
# Usage examples:
#  ./run.py                 # run locally
#  ./run.py REMOTE=1 HOST=1.2.3.4 PORT=1337  # connect to remote
#  ./run.py GDB=1           # run under gdb
#  ./run.py LIBC=./libc.so.6  # load specific libc for symbols


# ---------- CONFIG ----------
BINARY_PATH = "./pwn107-1644307530397.pwn107"           # <<-- change to target binary
HOST = os.getenv("HOST","10.49.160.178")
PORT = int(os.getenv("PORT",9007))
elf = ELF(BINARY_PATH)
context.binary=elf # change arch/endianness as needed
context.log_level='DEBUG' 

# ---------- START/CONNECT ----------
def start():
    """
    Start the process or connect to remote.
    Use command line flags:
      GDB=1      -> run under gdb
      REMOTE=1   -> connect to remote using HOST and PORT (or args.HOST/args.PORT)
    """
    
    
    if args.REMOTE:
        
        host = args.HOST if args.HOST else HOST
        port = int(args.PORT) if args.PORT else PORT
        shell = ssh(host=host, user='ctfuser', password='s3cret')
        lport = shell.forward_remote_port(9001)
        io = gdb.debug([BINARY_PATH], ssh=shell, gdbscript='''
            break main
            continue
        ''')
        return io
        # return remote(host, port)
    elif args.GDB:
        io = gdb.debug(BINARY_PATH, aslr=False, gdbscript='''
            break main
            continue
        ''')
        return io
    else:
        return process([BINARY_PATH])

# ---------- HELPERS ----------
def u64_safe(x):
    x = x.ljust(8, b"\x00")
    return u64(x)

# simple wrappers for clarity
def sl(io, data): io.sendline(data)
def s(io, data): io.send(data)
def r(io): return io.recv()
def ru(io, s, drop=True): return io.recvuntil(s, drop)
def rl(io): return io.recvline()

# ---------- EXPLOIT ----------
def exploit(io):
    print(r(io))
    
    sl(io, b"2")  
    
    print(r(io))
    sl(io, b"2")  
    io.interactive()

# ---------- MAIN ----------
if __name__ == "__main__":
    io = start()
    try:
        exploit(io)
    except KeyboardInterrupt:
        io.close()
        
        raise