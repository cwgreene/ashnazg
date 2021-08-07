import angr

p = angr.Project("./nocanarypie2")
s = p.factory.entry_state()
s.options.add(angr.sim_options.SHORT_READS)
s.options.add(angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
#s.options.add(angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY)
sm = p.factory.simgr(s)

r= sm.explore(find=0x00400781)
print(r)
for c in (r.found[0].solver.constraints):
    print(c)
print()
r.found[0].solver.simplify()
for c in (r.found[0].solver.constraints):
    print(c)

print(r.found[0])

sm = p.factory.simgr(s)

r = sm.explore(find=0x00400721)
print(r.found)
print(r.found[0].posix.dumps(0))
