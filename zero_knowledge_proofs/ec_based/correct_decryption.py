from petlib.ec import EcGroup, Bn
from primitives.elgamal import KeyPair
from primitives.hash_function import compute_challenge


class ProofCorrectDecryption:
    """
    Given a ciphertext and a plaintext, prove that decryption was performed correctly.
    """

    def __init__(self, kp, ciphertext, plaintext):
        self.group = kp.group
        self.infinity = self.group.infinite()
        self.order = self.group.order()
        self.pk = kp.pk
        self.generator = self.group.generator()

        random_announcement = self.order.random()
        self.announcement = random_announcement * ciphertext.c1

        challenge = compute_challenge(
            ciphertext.tolist() + [plaintext] + [self.announcement] + [self.order],
            self.order
        )

        self.response = random_announcement + challenge * kp.sk

    def verify(self, ciphertext, plaintext):
        """Verify proof
        Example:
            >>> G = EcGroup()
            >>> kp = KeyPair(G)
            >>> msg = 20 * G.generator()
            >>> ctxt = kp.pk.encrypt(msg)
            >>> msg_recovered = ctxt.decrypt(kp.sk)
            >>> proof = ProofCorrectDecryption(kp, ctxt, msg_recovered)
            >>> proof.verify(ctxt, msg_recovered)
            True
        """
        challenge = compute_challenge(
            ciphertext.tolist() + [plaintext] + [self.announcement] + [self.order],
            self.order
        )

        return challenge * plaintext - self.announcement == challenge * ciphertext.c2 - self.response * ciphertext.c1

    if __name__ == '__main__':
        import doctest
        doctest.testmod()

