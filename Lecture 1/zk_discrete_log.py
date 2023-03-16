import random
import hashlib

from typing import Tuple

# Relevant sources:
# https://people.eecs.berkeley.edu/~jfc/cs174/lecs/lec24/lec24.pdf
# https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic

LARGE_PRIME = 273389558745553615023177755634264971227
GENERATOR = 29155293994990157899330610805491402811 # random.randint(1, LARGE_PRIME)

def hash_helper(g, y, t, p) -> int:
    c_sha = hashlib.sha3_256((str(g) + str(y) + str(t)).encode()) # verifier random challenge
    c = int(c_sha.hexdigest(), 16) % p # modulo to reduce size
    return c

# This is the prover (non-interactive)
# x = secret
# g = generator
# p = large prime for the field
# Returns: residual (y) and proof of knowledge (pf)
def discreteLogProof(x, g ,p) -> Tuple[int, int]:
    y = pow(g, x, p) # public
    r = random.randint(0, p) # prover random bit
    t = pow(g, r, p) # prover to verifier 
    c = hash_helper(g, y, t, p) # modulo to reduce size
    s = (c * x + r) % (p - 1) # the proof, (p-1) because it is phi(p). phi(p) = p-1 for any prime p.
    pf = (s, t)
    # print("Y", y)
    # print("R", r)
    # print("T", t)
    # print("C", c)
    # print("S", s)
    # print("PF", pf)
    return (y, pf)

# This is the verifier
def verifiyProof(y, g, p, pf) -> bool:
    s, t = pf
    c = hash_helper(g, y, t, p)
    return pow(g, s, p) == ((t * pow(y, c, p)) % p)

def main():
    x = 150
    y, pf = discreteLogProof(x, GENERATOR, LARGE_PRIME)
    result = verifiyProof(y, GENERATOR, LARGE_PRIME, pf)
    print("Discrete Log Proof:", y, pf)
    print("Verify Proof:", result)

main()