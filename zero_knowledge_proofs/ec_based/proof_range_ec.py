from petlib.ec import EcGroup, Bn
from primitives.pedersen import PublicKey, Commitment
from primitives.hash_function import compute_challenge
from zero_knowledge_proofs.ec_based.proof_square_ec import ProofSameLog, ProofSquare


class ProofRange:
    """
    We compute the range proof following 'An Efficient Range Proof Scheme', from Pen and Bao. Note that here we are
    working with cyclic groups over elliptic curves. This code should be changed if we want to use it over finite
    fields.
    """
    def __init__(self, com_pk, number, commitment_number, random_commitment, lower_bound, upper_bound, security_parameter_1=120, security_parameter_2=250):
        """
        Genearte the proof that number 'number' is between 'lower_bound' and 'upper_bound'

        Attention with the choices of these parameters
        :param security_parameter_1: small (but sufficiently large number) 160
        :param security_parameter_2: Number bigger than the order of the group we are working on (in this case 224, so
        we are safe to go with 250, If we work with RSA, it should be bigger.
        """
        self.com_pk = com_pk
        self.security_parameter_1 = Bn.from_num(2).pow(security_parameter_1)
        self.security_parameter_2 = Bn.from_num(2).pow(security_parameter_2)

        self.order = self.com_pk.order

        self.commitment_one = commitment_number.commitment - (lower_bound - 1) * self.com_pk.generators[0]
        self.commitment_two = (upper_bound + 1) * self.com_pk.generators[0] - commitment_number.commitment

        random_commitment_difference = self.security_parameter_2.random()
        self.commitment_difference_bound_number = Commitment(
            (upper_bound - number + 1) * self.commitment_one +
            random_commitment_difference * self.com_pk.generators[1]
        )

        # Proof that commitment_difference_bound_number and commitment_two have the same log
        self.proof_same_log = ProofSameLog(
            upper_bound - number + 1, - random_commitment, random_commitment_difference,
            self.com_pk.generators[0], self.com_pk.generators[1], self.commitment_one, self.com_pk.generators[1],
            self.order
        )

        root_to_square = self.security_parameter_2.random()
        random_commitment_square = self.security_parameter_2.random()
        self.commitment_square = Commitment(
            root_to_square.mod_pow(2, self.order) * self.commitment_difference_bound_number.commitment +
            random_commitment_square * self.com_pk.generators[1]
        )

        self.com_pk_commitment_square = PublicKey(com_pk.group, 1)
        self.com_pk_commitment_square.generators[0] = self.commitment_difference_bound_number.commitment
        # proof that it is a square
        self.proof_square = ProofSquare(
            self.com_pk_commitment_square, root_to_square, self.commitment_square, random_commitment_square
        )

        value_to_find_sum = root_to_square ** 2 * (number - lower_bound + 1) * (upper_bound - number + 1)

        m_4 = self.security_parameter_2.random()
        m_3 = m_4.pow(2)
        m_2 = self.security_parameter_2.random()
        m_1 = value_to_find_sum - m_3 - m_2

        commitment_of_summed = root_to_square ** 2 * \
                               ((upper_bound - number + 1) * random_commitment + random_commitment_difference) + \
                               random_commitment_square

        r_3 = self.security_parameter_2.random()
        r_2 = self.security_parameter_2.random()
        r_1 = commitment_of_summed - r_3 - r_2

        self.commitment_m_1 = self.com_pk.commit([m_1], r_1)
        self.commitment_m_2 = self.com_pk.commit([m_2], r_2)
        self.commitment_m_3 = self.commitment_square.commitment - self.commitment_m_1.commitment - self.commitment_m_2.commitment

        self.proof_square_2 = ProofSquare(
            self.com_pk, m_4, self.commitment_m_3, r_3
        )

        # todo: challenge not properly computed. Check the security considerations
        self.challenge_1 = compute_challenge([self.commitment_m_1, self.commitment_m_2, self.commitment_m_3], self.security_parameter_1)
        self.challenge_2 = compute_challenge([self.commitment_m_1, self.commitment_m_2, self.commitment_m_3], self.security_parameter_1)

        self.response_ms_1 = self.challenge_1 * m_1 + m_2 + m_3
        self.response_ms_2 = m_1 + self.challenge_2 * m_2 + m_3
        self.response_rs_1 = self.challenge_1 * r_1 + r_2 + r_3
        self.response_rs_2 = r_1 + self.challenge_2 * r_2 + r_3

    def verify(self, com_pk, commitment_number, lower_bound, upper_bound):
        """
        Verify the proof

        Example:
            >>> G = EcGroup()
            >>> com_pk = PublicKey(G, 1)
            >>> order = com_pk.order
            >>> number = Bn.from_num(7)
            >>> random_commitment = order.random()
            >>> commitment = com_pk.commit([number], random_commitment)
            >>> lower_bound = Bn.from_num(3)
            >>> upper_bound = Bn.from_num(9)
            >>> proof = ProofRange(com_pk, number, commitment, random_commitment, lower_bound, upper_bound)
            >>> proof.verify(com_pk, commitment, lower_bound, upper_bound)
            True

            Should not verify
            >>> upper_bound = Bn.from_num(5)
            >>> proof = ProofRange(com_pk, number, commitment, random_commitment, lower_bound, upper_bound)
            >>> proof.verify(com_pk, commitment, lower_bound, upper_bound)
            False

            Should not verify
            >>> number = Bn.from_num(2)
            >>> random_commitment = order.random()
            >>> commitment = com_pk.commit([number], random_commitment)
            >>> proof = ProofRange(com_pk, number, commitment, random_commitment, lower_bound, upper_bound)
            >>> proof.verify(com_pk, commitment, lower_bound, upper_bound)
            False

        """
        check1 = self.proof_same_log.verify(
            self.commitment_two, self.commitment_difference_bound_number,
            com_pk.generators[0], com_pk.generators[1], self.commitment_one, com_pk.generators[1]
        )
        check2 = self.proof_square.verify(self.com_pk_commitment_square, self.commitment_square)

        check3 = self.proof_square_2.verify(com_pk, self.commitment_m_3)

        check4 = self.commitment_one == commitment_number.commitment - (lower_bound - 1) * com_pk.generators[0]
        check5 = self.commitment_two == (upper_bound + 1) * com_pk.generators[0] - commitment_number.commitment
        check6 = self.commitment_square.commitment == self.commitment_m_1.commitment + self.commitment_m_2.commitment + \
                 self.commitment_m_3

        self.challenge_1 = compute_challenge([self.commitment_m_1, self.commitment_m_2, self.commitment_m_3],
                                             self.security_parameter_1)
        self.challenge_2 = compute_challenge([self.commitment_m_1, self.commitment_m_2, self.commitment_m_3],
                                             self.security_parameter_1)


        check7 = self.challenge_1 * self.commitment_m_1.commitment + self.commitment_m_2.commitment + \
                 self.commitment_m_3 == self.response_ms_1 * com_pk.generators[0] + self.response_rs_1 * com_pk.generators[1]
        check8 = self.commitment_m_1.commitment + self.challenge_2 * self.commitment_m_2.commitment + \
                 self.commitment_m_3 == self.response_ms_2 * com_pk.generators[0] + self.response_rs_2 * com_pk.generators[1]

        # x > 0
        # y > 0
        check9 = self.response_ms_1.repr()[0] != '-'
        check10 = self.response_ms_2.repr()[0] != '-'

        return check1 and check2 and check3 and check4 and check5 and check6 and check7 and check8 and check9 and check10


if __name__=="__main__":
   import doctest

   doctest.testmod()
