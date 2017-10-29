import sys

PRINTABLE = 0x1
SIMPLE    = 0x2
IDENT     = 0x4

okchars = [0]*256

alpha   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_'
num     = '0123456789'
other   = '-~`!@#$%^&()=+{}[]|\';?/><.,'
special = '"*:\\\n '

printable = alpha + num + other + special
simple    = alpha + num + other
ident     = alpha + num + '-'

# printable letters
for c in printable:
	okchars[ord(c)] |= PRINTABLE

# simple values
for c in simple:
	okchars[ord(c)] |= SIMPLE

# identifiers (after the first char, which is checked manually)
for c in ident:
	okchars[ord(c)] |= IDENT

for b, v in enumerate(okchars):
	if b % 32 == 0:
		sys.stdout.write('\t')

	sys.stdout.write(str(v))

	if b < 255:
		sys.stdout.write(',')

	if (b + 1) % 32 == 0:
		sys.stdout.write('\n')
	else:
		sys.stdout.write(' ')
