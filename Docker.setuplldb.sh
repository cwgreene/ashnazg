for x in $(ls /usr/lib/llvm-14/lib/python3.10/dist-packages/lldb/); do
    ln -s "/usr/lib/llvm-14/lib/python3.10/dist-packages/lldb/$x" "/usr/lib/python3/dist-packages/lldb/$x"
done
