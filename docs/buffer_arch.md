# Ideas for architecture for buffers.
So we want to be able to list the buffers in a function

```py
function.list_buffers()
```

But we also want to be able to filter said buffers to
the ones that we can read from

```py
[buffer for buffer in buffers if buffer.is_readable()]
```

When a buffer is determined to be readable, it'd probably be
nice to then populate a "read" function which selects a
suitable read site to navigate to.

Though that might have to wait until we start getting into
proper planning mode.
