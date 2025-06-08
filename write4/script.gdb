break print_file

# mov gadget
break *0x08048543

# Breakpoint on shared library load
catch load

# Run until the .so is loaded
run < <(python challenge.py)
break *pwnme+177

# info proc mappings -- cool command
