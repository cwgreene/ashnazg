```
Ash nazg durbatulûk, ash nazg gimbatul,
ash nazg thrakatulûk agh burzum-ishi krimpatul.
```
# Ashnazg
Ashnazg is a library and tool for developing binary
exploits. It brings together a number of different
tools, Ghidra, `dorat`, `ROPgadget`, `pwntools`, `angr`,
smrop, and binds them together to pop shells.

# Testing
Run `pytest -vvv`

# Example
Ashnazg is intended to make it possible to describe
exploits at a high level.
```
import ashnazg

from ashnazg.assumptions import *

nazg = ashnazg.Ashnazg(binary="./target", libc="./libc.so.6")

# find a vulnerable function
vuln = list(nazg.find_vulnerable_functions())[0]
print(vuln.type) # says 'GETS' vulnerability

# begin exploit
conn = nazg.connect()

# get the program to the vulnerable function
# input.
conn.navigate(vuln.addr)

# 'GETS' vulnerability can be applied immediately if
# Binary is neither PIE nor canary. This is
# automatically detected, but we explicitly assume
# it here.
conn.exploit(vuln, assume=[NO_PIE, NO_CANARY])

# you have a shell
conn.interactive()
```

# Demos
https://asciinema.org/a/LX41I396nYxD84xqgnLtKQPIC
