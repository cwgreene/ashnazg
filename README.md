```
Ash nazg durbatulûk, ash nazg gimbatul,
ash nazg thrakatulûk agh burzum-ishi krimpatul.
```
# Ashnazg
Ashnazg is a library and tool for developing binary
exploits. It brings together a number of different
tools, Ghidra, `dorat`, `ROPgadget`, `pwntools`, `angr`,
smrop, and binds them together to pop shells.

# Install
The docker file should contain all steps needed to get
ashnazg running. If you want to set this up outside
of docker, then the dependencies for ubuntu are there,
along with the black magic invocations for making lldb
work with python on ubuntu.

Once running, you can run pytest.

# Testing
Run `pytest -vvv`
Run `pytest -vvv -n auto`

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
Old version (before auto prefix handling)
- https://asciinema.org/a/LX41I396nYxD84xqgnLtKQPIC

Fully exploitable corctf demo
- https://asciinema.org/a/tn2gBiwjWzLHne4AtaVX1tIz0

More verbose demo:
- https://asciinema.org/a/lIQThQCcHrafBRyfuNCmbxR50

# Setting up Virtual Env
lldb seems to be a bit of a problem. It can't be installed
via pip, so you probably need to link to your system's install
via a symlink instead. Blech.
