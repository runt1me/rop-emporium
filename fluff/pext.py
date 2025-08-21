def pext(src, mask):
    """Simulate x86 BMI2 pext for 32-bit values."""
    dst = 0
    out_bit = 0
    bit = 0
    while bit < 32:
        if (mask >> bit) & 1:
            if (src >> bit) & 1:
                dst |= (1 << out_bit)
            out_bit += 1
        bit += 1
    return dst

def mask_for_byte(target_byte, src=0xB0BABABA):
    """
    Build a 32-bit mask (for EBP) so that:
      pext( src=0xB0BABABA, mask=EBP ) & 0xFF == target_byte

    Returns:
      mask (int) suitable for loading into EBP.
    """
    if isinstance(target_byte, bytes):
        if len(target_byte) != 1:
            raise ValueError("Provide a single byte.")
        target = target_byte[0]
    else:
        target = int(target_byte) & 0xFF

    # Desired bits, LSB-first order for PEXT packing
    desired_bits = [(target >> i) & 1 for i in range(8)]

    positions = []
    bit_idx = 0
    for want in desired_bits:
        # Find next source bit equal to 'want'
        while bit_idx < 32 and ((src >> bit_idx) & 1) != want:
            bit_idx += 1
        if bit_idx >= 32:
            raise RuntimeError("Could not find enough matching bits in source.")
        positions.append(bit_idx)
        bit_idx += 1  # ensure strictly increasing positions

    # Build mask with ones at the selected positions
    mask = 0
    for i in positions:
        mask |= (1 << i)

    # Sanity-check
    assert (pext(src, mask) & 0xFF) == target, "Internal error: mask does not produce target byte"
    return mask

if __name__ == "__main__":
    input_bytes = [0x66, 0x6c, 0x61, 0x67, 0x2e, 0x74, 0x78]
    for input_byte in input_bytes:
        print(f"Input byte: {input_byte}")

        m = mask_for_byte(input_byte)
        print(hex(m))
