from primitives.algebra_lib import FFGroup, FFElement
from petlib.bn import Bn
from primitives.pedersen import PublicKey, Commitment
from primitives.hash_function import compute_challenge


class ProofSquare:
    """We provide proof that a committed value is a square. We follow the description of
    Efficient Proofs that a Committed Number Lies in an Interval from Fadrice Boudot. Note that here we are
    working with cyclic groups over elliptic curves. This code should be changed if we want to use it over finite
    fields. """
    def __init__(self, com_pk, sqr_root, commitment_sqr, random_commitment, security_parameter=128):
        self.order = com_pk.order
        self.group = com_pk.group

        self.security_space = self.order * Bn.from_num(2).mod_pow(security_parameter, self.order)
        random_commitment_sqr_root = self.security_space.random()
        self.commitment_sqr_root = com_pk.commit([sqr_root], random_commitment_sqr_root)

        random_commitment_sqr = (random_commitment - sqr_root * random_commitment_sqr_root).mod(self.order)

        # Commitment with the previous commitment as a generator
        generator_1 = self.commitment_sqr_root.commitment
        generator_com_pk_1 = com_pk.generators[0]
        generator_com_pk_2 = com_pk.generators[1]

        self.commitment_sqr = Commitment(generator_1 ** sqr_root * generator_com_pk_2 ** random_commitment_sqr)

        # Now we need to proof that commitment_sqr_root and commitment_sqr hide the same value

        self.proof_same_log = ProofSameLog(
            sqr_root, random_commitment_sqr_root, random_commitment_sqr, generator_com_pk_1, generator_com_pk_2,
            generator_1, generator_com_pk_2, self.order
        )

    def verify(self, com_pk, commitment_sqr):
        """
        Verification of the proof

        Example:
            >>> G = FFGroup()
            >>> com_pk = PublicKey(G, 1)
            >>> order = com_pk.order
            >>> sqr_root = Bn.from_num(5)
            >>> sqr = Bn.from_num(25)
            >>> random_commitment = order.random()
            >>> commitment_sqr = com_pk.commit([sqr], random_commitment)

            >>> proof = ProofSquare(com_pk, sqr_root, commitment_sqr, random_commitment)
            >>> proof.verify(com_pk, commitment_sqr)
            True

            Following should fail
            >>> sqr = Bn.from_num(17)
            >>> random_commitment = order.random()
            >>> commitment_sqr = com_pk.commit([sqr], random_commitment)

            >>> proof = ProofSquare(com_pk, sqr_root, commitment_sqr, random_commitment)
            >>> proof.verify(com_pk, commitment_sqr)
            False

        """

        return self.proof_same_log.verify(
            self.commitment_sqr_root, commitment_sqr, com_pk.generators[0], com_pk.generators[1],
            self.commitment_sqr_root.commitment, com_pk.generators[1]
        )


class ProofSameLog:
    """
    Proof that two commitments have the same discrete log. We need to work with bases that belong to the same
    group
    """
    def __init__(self, exponent, random_commitment_one, random_commitment_two, base_g_one, base_h_one, base_g_two, base_h_two, order, security_parameter=128):
        self.order = order
        self.security_space = self.order * Bn.from_num(2).mod_pow(security_parameter, self.order)

        random_hiding_exponent = self.security_space.random()
        random_hiding_commitment_one = self.security_space.random()
        random_hiding_commitment_two = self.security_space.random()

        commitment_one = Commitment(base_g_one ** random_hiding_exponent * base_h_one ** random_hiding_commitment_one)
        commitment_two = Commitment(base_g_two ** random_hiding_exponent * base_h_two ** random_hiding_commitment_two)

        self.challenge = compute_challenge([commitment_one] + [commitment_two], self.order)

        self.response_exponent = random_hiding_exponent + self.challenge * exponent
        self.response_random_one = random_hiding_commitment_one + self.challenge * random_commitment_one
        self.response_random_two = random_hiding_commitment_two + self.challenge * random_commitment_two

    def verify(self, commitment_one, commitment_two, base_g_one, base_h_one, base_g_two, base_h_two):
        """
        Verification.
        Example:
            >>> G = FFGroup()
            >>> com_pk = PublicKey(G, 1)
            >>> order = com_pk.order
            >>> shared_exponent = Bn.from_num(25)
            >>> random_commitment = order.random()
            >>> commitment_one = com_pk.commit([shared_exponent], random_commitment)
            >>> random_commitment_two = order.random()
            >>> commitment_two = Commitment(commitment_one.commitment ** shared_exponent * commitment_one.commitment ** random_commitment_two)

            >>> proof = ProofSameLog(shared_exponent, random_commitment, random_commitment_two, com_pk.generators[0], com_pk.generators[1], commitment_one.commitment, commitment_one.commitment, order)
            >>> proof.verify(commitment_one, commitment_two, com_pk.generators[0], com_pk.generators[1], commitment_one.commitment, commitment_one.commitment)
            True

            Should not verify
            >>> shared_exponent = Bn.from_num(27)
            >>> random_commitment = order.random()
            >>> commitment_one = com_pk.commit([shared_exponent], random_commitment)
            >>> random_commitment_two = order.random()
            >>> commitment_two = Commitment(commitment_one.commitment ** Bn.from_num(25) * commitment_one.commitment ** random_commitment_two)

            >>> proof = ProofSameLog(shared_exponent, random_commitment, random_commitment_two, com_pk.generators[0], com_pk.generators[1], commitment_one.commitment, commitment_one.commitment, order)
            >>> proof.verify(commitment_one, commitment_two, com_pk.generators[0], com_pk.generators[1], commitment_one.commitment, commitment_one.commitment)
            False


        """
        if type(commitment_one) == Commitment:
            commitment_one = commitment_one.commitment

        if type(commitment_two) == Commitment:
            commitment_two = commitment_two.commitment

        return self.challenge == compute_challenge(
            [base_g_one ** self.response_exponent *
             base_h_one ** self.response_random_one *
             commitment_one ** self.challenge.int_neg().mod(self.order)] +
            [base_g_two ** self.response_exponent *
             base_h_two ** self.response_random_two *
             commitment_two ** self.challenge.int_neg().mod(self.order)], self.order
        )

if __name__ == '__main__':
    import doctest

    doctest.testmod()

