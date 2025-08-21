# Breakpoint on shared library load
catch load

# Run until the .so is loaded
run < <(python challenge.py)
break *pwnme+273

# Break on my patch byte gadget
# break *0x080485b8

# other commands
# info proc mappings
# maintenance info sections
