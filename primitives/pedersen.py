from petlib.ec import EcGroup, EcPt, Bn
from primitives.algebra_lib import FFGroup, FFElement
import numpy as np


class PublicKey:
    """Simple public key for Pedersen's commitment scheme"""

    def __init__(self, group, n):
        """Create a public key for the Pedersen commitment scheme.
        Create a public key for a Pedersen commitment scheme in group `group` for n
        elements. We set the bases by hashing integers to points on the curve.
        Example:
            >>> G = EcGroup()
            >>> pk = PublicKey(G, 2)

            >>> G = FFGroup()
            >>> pk = PublicKey(G, 2)
        """

        self.group = group
        self.order = self.group.order()
        self.n = n
        self.generators = [self.group.hash_to_point(str(i).encode()) for i in range(n + 1)]
        self.generators = np.array(self.generators)

    def commit(self, values, randomizer=None):
        """Commit to a list of values
        Returns the Commitment.
        The randomizer can also be passed in as the optional parameter.
        Example:
            >>> G = EcGroup()
            >>> pk = PublicKey(G, 2)
            >>> com = pk.commit([10, 20])

            >>> G = FFGroup()
            >>> pk = PublicKey(G, 2)
            >>> com = pk.commit([Bn.from_num(10), Bn.from_num(20)])
        """
        if len(values) != self.n:
            raise RuntimeError(
                "Incorrect length of input {0} expected {1}".format(len(values), self.n)
            )

        if randomizer is None:
            randomizer = self.group.order().random()

        powers = np.array(values + [randomizer])

        if type(self.group) == EcGroup:
            commitment = Commitment(np.sum(powers * self.generators))
        elif type(self.group) == FFGroup:
            commitment = Commitment(np.prod([a ** b for a, b in zip(self.generators, powers)]))

        return commitment


class Commitment:
    """A Pedersen commitment"""

    def __init__(self, commitment):
        self.commitment = commitment

    def __mul__(self, other):
        """Multiply two Pedersen commitments
        The commitment scheme is additively homomorphic. Multiplying two
        commitments gives a commitment to the pointwise sum of the original
        values.
        Example:
            >>> G = EcGroup()
            >>> order = G.order()
            >>> pk = PublicKey(G, 2)
            >>> rand1 = order.random()
            >>> rand2 = order.random()
            >>> com1 = pk.commit([10, 20], rand1)
            >>> com2 = pk.commit([13, 19], rand2)
            >>> comsum = com1 * com2
            >>> com = pk.commit([23, 39], randomizer=rand1 + rand2)
            >>> com == comsum
            True

            >>> G_ff = FFGroup()
            >>> order = G_ff.order()
            >>> pk_ff = PublicKey(G_ff, 2)
            >>> rand1 = order.random()
            >>> rand2 = order.random()
            >>> com1 = pk_ff.commit([Bn.from_num(10), Bn.from_num(20)], rand1)
            >>> com2 = pk_ff.commit([Bn.from_num(13), Bn.from_num(19)], rand2)
            >>> comsum_ff = com1 * com2
            >>> com_ff = pk_ff.commit([Bn.from_num(23), Bn.from_num(39)], randomizer=rand1 + rand2)
            >>> com_ff == comsum_ff
            True
        """
        if type(self.commitment) == EcPt:
            return Commitment(self.commitment + other.commitment)
        elif type(self.commitment) == FFElement:
            return Commitment(self.commitment * other.commitment)
        else:
            raise ValueError("unexpected group type. Only prepared to work with EcPt or FFElements")

    def __pow__(self, exponent):
        """Raise Pedersen commitment to the power of a constant
        The commitment scheme is additively homomorphic. Raising a commitment
        to a constant power multiplies the committed vector by that constant.
        Example:
            >>> G = EcGroup()
            >>> order = G.order()
            >>> pk = PublicKey(G, 2)
            >>> rand1 = order.random()
            >>> com1 = pk.commit([10, 20], rand1)
            >>> commul = com1 ** 10
            >>> com = pk.commit([100, 200], randomizer=10 * rand1)
            >>> com == commul
            True

            >>> G_ff = FFGroup()
            >>> order_ff = G_ff.order()
            >>> pk_ff = PublicKey(G_ff, 2)
            >>> rand1_ff = order_ff.random()
            >>> com1_ff = pk_ff.commit([Bn.from_num(10), Bn.from_num(20)], rand1_ff)
            >>> commul_ff = com1_ff ** Bn.from_num(10)
            >>> com_ff = pk_ff.commit([Bn.from_num(100), Bn.from_num(200)], randomizer=10 * rand1_ff)
            >>> com_ff == commul_ff
            True
        """
        if type(self.commitment) == EcPt:
            return Commitment(exponent * self.commitment)
        elif type(self.commitment) == FFElement:
            return Commitment(self.commitment ** exponent)
        else:
            raise ValueError("unexpected group type. Only prepared to work with EcPt or FFElements")


    def __truediv__(self, other):
        """
        Commitment division
        Example:
            >>> G = EcGroup()
            >>> order = G.order()
            >>> pk = PublicKey(G, 2)
            >>> rand1 = order.random()
            >>> rand2 = order.random()
            >>> com1 = pk.commit([10, 20], rand1)
            >>> com2 = pk.commit([5, 5], rand2)
            >>> comsum = com1 / com2
            >>> com = pk.commit([5, 15], randomizer=rand1 - rand2)
            >>> com == comsum
            True

            >>> G_ff = FFGroup()
            >>> order = G_ff.order()
            >>> pk_ff = PublicKey(G_ff, 2)
            >>> rand1 = order.random()
            >>> rand2 = order.random()
            >>> com1 = pk_ff.commit([Bn.from_num(10), Bn.from_num(20)], rand1)
            >>> com2 = pk_ff.commit([Bn.from_num(5), Bn.from_num(5)], rand2)
            >>> comsum_ff = com1 / com2
            >>> com_ff = pk_ff.commit([Bn.from_num(5), Bn.from_num(15)], randomizer=(rand1 - rand2).mod(order))
            >>> com_ff == comsum_ff
            True
        """
        if type(self.commitment) == EcPt:
            return Commitment(self.commitment - other.commitment)
        elif type(self.commitment) == FFElement:
            return Commitment(self.commitment / other.commitment)
        else:
            raise ValueError("unexpected group type. Only prepared to work with EcPt or FFElements")

    def __eq__(self, other):
        return self.commitment == other.commitment

    def export(self):
        return self.commitment.export()


if __name__ == "__main__":
    import doctest

    doctest.testmod()