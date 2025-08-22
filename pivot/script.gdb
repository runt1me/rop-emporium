# Breakpoint on shared library load
catch load

# Run until the .so is loaded
break *pwnme+198
break foothold_function

# Gadget breakpoints

# read gadget
break *0x08048830

# add gadget
break *0x8048833

# stack pivot gadget
break *0x0804882e

# other commands
# info proc mappings
# maintenance info sections
