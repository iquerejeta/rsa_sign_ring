from petlib.ec import EcGroup
from primitives.algebra_lib import FFGroup
from primitives.hash_function import compute_challenge
from math import gcd


import random


class KeyPair:
    """ElGamal key pair"""
    # todo: repair the code to work with FFGroup s.
    def __init__(self, group):
        self.group = group
        self.sk = self.group.order().random()
        if type(self.group) == EcGroup:
            self.pk = PublicKey(self.group, self.sk * self.group.generator())
        elif type(self.group) == FFGroup:
            self.pk = PublicKey(self.group, self.group.generator ** self.sk)


class PublicKey:
    """ElGamal Public Key"""

    def __init__(self, group, pk):
        self.group = group
        self.order = self.group.order()
        self.pk = pk
        self.generator = self.group.generator()

    def get_randomizer(self):
        """Return a random value from the publickey randomizer's space"""
        return self.group.order().random()

    def encrypt(self, msg, ephemeral_key=None):
        """Encrypt a message
        :param msg: Message to encrypt (must be part of the group)
        :param ephemeral_key: Randomizer of encryption. This should be empty except if we need the randomizer to
        generate a proof of knowledge which requires the randomizer
        :return: Encryption of msg.
        """
        generator = self.group.generator()
        if ephemeral_key is None:
            ephemeral_key = self.order.random()
        if type(self.group) == EcGroup:
            return Ciphertext(ephemeral_key * generator, ephemeral_key * self.pk + msg)
        elif type(self.group) == FFGroup:
            return Ciphertext(generator ** ephemeral_key, msg * (self.pk ** ephemeral_key))
        else:
            raise ValueError("Expecting to work with EcGroup or FFGroup")

    def reencrypt(self, ctxt, ephemeral_key=None):
        """Reencrypt a ciphertext
        :param ctxt:
        :param ephemeral_key: randomness of reencryption.
        :return: Reencryption of ctxt
        """
        self.infinity = self.group.infinite()

        if ephemeral_key is None:
            ephemeral_key = self.order.random()
        zero_encryption = self.encrypt(self.infinity, ephemeral_key=ephemeral_key)

        return ctxt * zero_encryption

    def sign(self, message, sk):
        """ECDSA signature"""
        if type(self.group) == EcGroup:
            hashed_message = compute_challenge([message], self.order)
            random_value = self.order.random() # should not equal zero. when properly implemented, verify
            random_point = random_value * self.generator
            x = 0
            while x == 0:
                x = random_point.get_affine()[0].mod(self.order)

            signature = (random_value.mod_inverse(self.order) * (hashed_message + x * sk)).mod(self.order)

            return x, signature

        elif type(self.group) == FFGroup:
            raise NotImplementedError("Soon come, soon come.")

    def verify_signature(self, message, signature_pair):
        """
        Verification.

        Example:
            >>> G = EcGroup()
            >>> kp = KeyPair(G)
            >>> pk = kp.pk
            >>> msg = 1024 * G.generator()
            >>> sig = pk.sign(msg, kp.sk)
            >>> pk.verify_signature(msg, sig)
            True

            >>> msg_fake = 111 * G.generator()
            >>> pk.verify_signature(msg_fake, sig)
            False

        """
        if type(self.group) == EcGroup:
            hashed_message = compute_challenge([message], self.order)
            verif_1 = hashed_message * signature_pair[1].mod_inverse(self.order)
            verif_2 = signature_pair[0] * signature_pair[1].mod_inverse(self.order)

            verif_point = verif_1 * self.generator + verif_2 * self.pk

            if verif_point.get_affine()[0] == signature_pair[0]:
                return True
            else:
                return False

        if type(self.group) == FFGroup:
            raise NotImplementedError("Probably will never come in the near future (13-06-2019)")

class Ciphertext:
    """ElGamal ciphertext """

    def __init__(self, c1, c2):
        self.c1 = c1
        self.c2 = c2
        self.group = self.c1.group

    def __mul__(self, other):
        """Multiply two ElGamal ciphertexts
        ElGamal ciphertexts are homomorphic. You can multiply two ciphertexts to add
        corresponding plaintexts.
        Example:
            >>> G = EcGroup()
            >>> kp = KeyPair(G)
            >>> ctxt1 = kp.pk.encrypt(10 * G.generator())
            >>> ctxt2 = kp.pk.encrypt(1014 * G.generator())
            >>> ctxt = ctxt1 * ctxt2
            >>> msg = ctxt.decrypt(kp.sk)
            >>> msg == 1024 * G.generator()
            True

            # >>> G_ff = FFGroup()
            # >>> kp = KeyPair(G_ff)
            # >>> ctxt1 = kp.pk.encrypt(10 * G.generator())
            # >>> ctxt2 = kp.pk.encrypt(1014 * G.generator())
            # >>> ctxt = ctxt1 * ctxt2
            # >>> msg = ctxt.decrypt(kp.sk)
            # >>> msg == 1024 * G.generator()
            # True
        """
        if type(self.group) == EcGroup:
            return Ciphertext(self.c1 + other.c1, self.c2 + other.c2)
        elif type(self.group) == FFGroup:
            return Ciphertext(self.c1 * other.c1, self.c2 * other.c2)
        else:
            raise ValueError("Expecting to work with EcGroup or FFGroup")

    def __pow__(self, exponent):
        """Raise ElGamal ciphertexts to a constant exponent
        ElGamal ciphertexts are homomorphic. You can raise a ciphertexts to a known
        exponent to multiply the corresponding plaintext by this exponent.
        Example:
            >>> G = EcGroup()
            >>> kp = KeyPair(G)
            >>> ctxt = kp.pk.encrypt(10 * G.generator()) ** 100
            >>> msg = ctxt.decrypt(kp.sk)
            >>> msg == 1000 * G.generator()
            True
        """
        return Ciphertext(exponent * self.c1, exponent * self.c2)

    def __eq__(self, other):
        return self.c1 == other.c1 and self.c2 == other.c2

    def weighted_sum(self, weights):
        return Ciphertext(self.group.wsum(weights, ))

    def decrypt(self, sk):
        """Decrypt ElGamal ciphertext
        Example:
            >>> G = EcGroup()
            >>> kp = KeyPair(G)
            >>> msg = 20 * G.generator()
            >>> ctxt = kp.pk.encrypt(msg)
            >>> msg_recovered = ctxt.decrypt(kp.sk)
            >>> msg == msg_recovered
            True
        """
        return self.c2 - sk * self.c1

    def tolist(self):
        """ Create a list out of the ciphertexts
        """
        return [self.c1, self.c2]

    def export(self):
        return


if __name__ == "__main__":
    import doctest
    doctest.testmod()