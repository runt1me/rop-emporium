break print_file

# Breakpoint on shared library load
catch load

# Run until the .so is loaded
run < <(python challenge.py)
break *pwnme+273

# info proc mappings -- cool command
