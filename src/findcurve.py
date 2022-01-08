#!/usr/bin/env sage

import sys
from sage.all import *

# The prime order of libsnark's BN128 curve
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
F = GF(r)

count = 0
primecount = 0
done = False
while not done:
    b = F.random_element()
    try:
		E = EllipticCurve(F, [-3, b])
		Ec = E.cardinality()
		count += 1
		print "b =", b, "Ec =", Ec, "c =", count, "pc =", primecount
		Etc = 2 * r + 2 - Ec
		if Ec in Primes():
			primecount += 1
			print "Ec is prime; primecount =", primecount
	    if Etc in Primes():
			print "Solution found:", b
			done = True
	except KeyboardInterrupt:
		print "Terminating on keyboard interrupt"
		sys.exit(1)
	except:
		pass
