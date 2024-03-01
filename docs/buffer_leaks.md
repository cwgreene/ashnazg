# Unterminated Buffer leak

1. how do we determine if a function has a memory leak?

1. Is there a non-null terminated buffer being written to?
  * Fgets doesn't work. sprintf won't work
  * read, fread work.
  * is it from stdin?

2. Is said buffer puts or printf'd?
  * need to fix printf to support symbols
  * puts is good to go

1. After initial detection, may want to validate that there isn't additional logic that sanitizes
and null terminates.
1. Acceptable outcomes:
    1. We print it immediately.
    1. We return it and get printed elsewhere.

# Forced example: Canary leak
1. Detect usage of `read` or `fread`.
2. Check if buffer is adjacent to canary.

Note, the canary example will also require a slight buffer overflow
as well to overwrite the existing null byte of the canary.

That said, we will still need the basic infrastructure here to
detect usage of fread and read, and track the buffer's usage
in the function to determine if it is user controlled and
eventually passed, within the function, to output.

MVP:
1. Find buffer writes that don't force null termination.
2. Determine if said buffer is passed, in the same function
to `puts`.
