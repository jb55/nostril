static inline int zero_bits(unsigned char b)
{
	int n = 0;

	if (b == 0)
		return 8;

	while (b >>= 1)
		n++;

	return 7-n;
}

/* find the number of leading zero bits in a hash */
static int count_leading_zero_bits(unsigned char *hash)
{
	int bits, total, i;

	for (i = 0, total = 0; i < 32; i++) {
		bits = zero_bits(hash[i]);
		total += bits;
		if (bits != 8)
			break;
	}
	return total;
}
