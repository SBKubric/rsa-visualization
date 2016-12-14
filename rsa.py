import math
import random
import time

'''
Euclid's algorithm for determining the greatest common divisor.
'''


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


'''
Euclid's extended algorithm for finding the multiplicative inverse of two numbers.
'''


def multiplicative_inverse(a, b):
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a  # Remember original a/b for removing
    ob = b  # negative values from return results
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += ob  # If negative, than wrap modulo orignal b
    if ly < 0:
        ly += oa  # If negative, than wrap modulo orignal a
    return lx


'''
Tests to see if a number is prime.
'''


def is_prime(num):
    if num in (2, 3):
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num ** 0.5) + 2, 2):
        if num % n == 0:
            return False
    return True


def generate_keypair(p, q):
    """
    Generating the pair of keys based on two prime numbers p and q
    :param p: the first prime
    :param q: the second prime
    :return: two tuples, which are keys
    """
    n = p * q
    # Phi is the totient of n
    phi = (p - 1) * (q - 1)
    # Choose an integer e such that e and phi(n) are coprime
    # Use Euclid's Algorithm to verify that e and phi(n) are coprime
    have_coprime = False
    while not have_coprime:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
        have_coprime = (g == 1)

    # Use Extended Euclid's Algorithm to generate the private key
    d = multiplicative_inverse(e, phi)

    # Return public and private keypair
    # Public key is (e, n) and private key is (d, n)
    return (e, n), (d, n)


def encrypt(pk, plaintext):
    """
    Encryption function
    :param pk: key
    :param plaintext: message to encrypt
    :return: cipher as the array of bytes
    """
    # Unpack the key into it's components
    e, n = pk
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [pow(ord(char), e, n) for char in plaintext]
    # Return the array of bytes
    return cipher


def decrypt(pk, ciphertext):
    """
    Decryption function
    :param pk: key
    :param ciphertext: cipher, received from enctypt(pk, plaintext) function
    :return: String of original message
    """
    # Unpack the key into its components
    d, n = pk
    # Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr(pow(char, d, n)) for char in ciphertext]
    # Return the array of bytes as a string
    return ''.join(plain)


def prime_factorization(n):
    """
    Finds the prime factors of `n`
    """
    prime_factors = []
    limit = int(math.sqrt(n)) + 1
    if n == 1:
        return [1]
    for check in range(2, limit):
        while n % check == 0:
            prime_factors.append(check)
            n /= check
    if n > 1:
        prime_factors.append(n)
    return prime_factors


def _backspace(message, p):
    return chr(8) * len(str(p))


def get_encrypted_str(cipher):
    """
    Transform the cipher to the Unicode characters
    :param cipher: The given encrypted message from encrypt(pk, plaintext)
    :return: String of Unicode characters
    """
    result_string = ''
    char_code = 0
    for number in cipher:
        num_string = str(number)
        for ch in num_string:
            if char_code*10 + int(ch) < 10000:
                char_code = char_code*10 + int(ch)
            else:
                result_string += chr(char_code)
                char_code = 0
        result_string += ' '
    return result_string


def get_some_primes():
    """
    Get the list of prime numbers in the given range
    :return: primes – list of prime numbers
    """
    # In fact, should be much more sophisticated method
    primes = []
    for x in range(29997800, 30000000):
        if is_prime(x):
            primes.append(x)
    return primes


def get_rand_p_and_q(primes):
    """
    Get random P and Q from primes list
    :param primes: list of prime numbers
    :return: tuple (p, q), p != q
    """
    p = primes[random.randrange(1, len(primes)) - 1]
    q = primes[random.randrange(1, len(primes)) - 1]
    while p == q:
        q = primes[random.randrange(1, len(primes)) - 1]
    return p, q


def terminal_mode():
    """
    The terminal mode of the algorithm
    :return: None
    """
    print('RSA Encrypter/ Decrypter')

    primes = get_some_primes()
    p, q = get_rand_p_and_q(primes)

    print('Generating your public/private keypairs now . . .')
    time.sleep(1)

    public, private = generate_keypair(p, q)
    print('Your public key is ', public, ' and your private key is ', private)

    default_msg = 'Hello RSA!'
    message = input("Enter a message to encrypt with your public key: {}".format(default_msg) + _backspace(
        default_msg, p)) or default_msg

    print('Your message is: {}\nEncrypting...'.format(message))

    cipher = encrypt(public, message)

    print('Your encrypted message is: ')

    print(get_encrypted_str(cipher))
    input('Press enter to decrypt.')
    print('Decrypting message with private key ', private, ' . . .')
    time.sleep(2)
    print('Your message is:')
    print(decrypt(private, cipher))


if __name__ == '__main__':
    terminal_mode()
