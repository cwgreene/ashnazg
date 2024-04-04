import string
try:
    import colorama
except:
    class fore:
        RED = b""
        BLUE =b""
        GREEN = b""
        CYAN = b""
        YELLOW = b""
        MAGENTA = b"" 
    class Colorama:
        def __init__(self):
            self.Fore = fore()
    colorama = Colorama()

            

def display_buffers(buffers, memory):
    # mark rsp to the left
    # mark canary (if present),rbp, rip
    mem = b""
    canary_start = len(memory)-0x10-0x8
    rbp_start = len(memory)-0x8-0x8
    rip_start = len(memory)-0x8

    colors =  list(map(lambda x: x.encode(),[colorama.Fore.RED, 
               colorama.Fore.BLUE, 
               colorama.Fore.GREEN,
               colorama.Fore.CYAN,
               colorama.Fore.YELLOW,
               colorama.Fore.MAGENTA]))
    
    for i, c in enumerate(memory):
        if i == canary_start:
            mem += colorama.Fore.RED.encode()
        elif i == rbp_start:
            mem += colorama.Fore.BLUE.encode()
        elif i == rip_start:
            mem += colorama.Fore.GREEN.encode()
        if c in string.printable.encode() and c not in b"\b\t\r\n":
            mem += bytes([c])
        else:
            mem += b"."
    print(mem.decode() + colorama.Fore.RESET)
    # for now do dumb check
    buffers_at_i = [[] for x in memory]
    buffer_colors = {}
    buffer_map = {}
    max_buffer_len = 0
    for i,c in enumerate(memory):    
        for buffer in buffers:
            start, end = buffer
            if i == start:
                buffer_map[buffer] = len(buffers_at_i[i])
                buffer_colors[buffer] = colors[len(buffers_at_i[i]) % len(colors)]
            if i >= start and i <= end:
                buffers_at_i[i].append(buffer)
                max_buffer_len = max(max_buffer_len, len(buffers_at_i[i]))

    for j in range(max_buffer_len):
        buffer_line = b""
        for i,c in enumerate(memory):
            for buffer in buffers_at_i[i]:
                if buffer_map[buffer] == j:
                    break
            else:
                buffer_line += b" "
            for buffer in buffers_at_i[i]:
                if buffer_map[buffer] != j:
                    continue
                start, end = buffer
                if i == start:
                    buffer_line += b"<"
                elif i == end:
                    buffer_line += b">"
                elif i > start and i < end:
                    buffer_line += str(buffers.index(buffer)).encode()
        print(buffer_line.decode())

display_buffers([(8,16), (24,32), (12,20)], b"hello   "+b"\x00"*64)