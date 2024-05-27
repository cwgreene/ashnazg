Context managers as a way of creating "transactions".

Here we see the idea of explicitly saying how to set the return
pointer by using "gets", and leaking, from the stack, using printf.

This suggests an idea of a "Manipulator" class that implements
these. Ideally we could also do `main.set_return` and let
ashnazg try to figure it out on it's own.

```
nazg = Ashnazg("./bap")

with nazg.navigate("main") as main:
    main.using("gets").set_return("main")
    main.using("printf").leak("libc", STACK)

# We now satisfy requirements for buffer overflow using gets
with nazg.current() as main:
    main.tactic(StackBufferOverflow(input="gets"))
```
