# Breakpoint on shared library load
catch load

# Run until the .so is loaded
run < <(python challenge.py)
break *pwnme+177

# Gadget breakpoints
# This gets hit right after edx has been set
break *0x08048558

# This one does the loading of the byte into ecx
# break *0x08048555

# other commands
# info proc mappings
# maintenance info sections
