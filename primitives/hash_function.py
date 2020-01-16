import hashlib
from petlib.ec import Bn


def compute_challenge(transcript, p):
    """
    Compute challenge given transcript
    """
    transcript = flatten(transcript)
    m = hashlib.sha512()
    for element in transcript:
        try:
            m.update(element.export())
        except AttributeError:
            try:
                m.update(hex(element).encode())
            except:
                m.update(element.hex().encode())

    hashed = m.hexdigest()

    return (Bn.from_hex(hashed)).mod(Bn.from_num(p))

def flatten(lst):
    return sum( ([x] if not isinstance(x, list) else flatten(x)
		     for x in lst), [] )