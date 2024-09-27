import random
import math
import json


def sieve_of_eratosthenes(limit):

    primes = []
    sieve = [True] * (limit + 1)
    sieve[0] = sieve[1] = False

    for start in range(2, limit + 1):
        if sieve[start]:
            primes.append(start)
            for multiple in range(start * start, limit + 1, start):
                sieve[multiple] = False

    return primes


def generate_prime_from_sieve(primes):

    return random.choice(primes)


def lcm(x, y):
    return x * y // math.gcd(x, y)


def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y


def generate_keypair(limit=1024):

    primes = sieve_of_eratosthenes(limit)

    p = generate_prime_from_sieve(primes)
    q = generate_prime_from_sieve(primes)
    while p == q:
        q = generate_prime_from_sieve(primes)

    n = p * q
    lamb = lcm(p - 1, q - 1)
    g = n + 1
    mu = modinv(lamb, n)
    public_key = (n, g)
    private_key = (lamb, mu, p, q)
    return public_key, private_key


def encrypt(public_key, plaintext):
    n, g = public_key
    n_sq = n * n
    r = random.randint(1, n - 1)
    while math.gcd(r, n) != 1:
        r = random.randint(1, n - 1)
    c = (pow(g, plaintext, n_sq) * pow(r, n, n_sq)) % n_sq
    return c


def serialize_data(public_key, data):
    encrypted_data_list = [encrypt(public_key, x) for x in data]
    encrypted_data = {
        'public_key': {'n': public_key[0], 'g': public_key[1]},
        'values': encrypted_data_list
    }
    serialized = json.dumps(encrypted_data)
    return serialized


def decrypt(private_key, public_key, ciphertext):
    n, g = public_key
    n_sq = n * n
    lamb, mu, p, q = private_key
    x = pow(ciphertext, lamb, n_sq) - 1
    l = (x // n) % n
    plaintext = (l * mu) % n
    return plaintext


def load_answer():
    with open('answer.json', 'r') as file:
        ans = json.load(file)
    return ans

public_key, private_key = generate_keypair()
print("Public Key:", public_key)
print("Private Key:", private_key)

keys = {
    'public_key': {'n': public_key[0], 'g': public_key[1]},
    'private_key': {'lamb': private_key[0], 'mu': private_key[1], 'p': private_key[2], 'q': private_key[3]}
}
with open('custkeys.json', 'w') as file:
    json.dump(keys, file)

data = [47, 5, 6, 1]
print("Original Data:", data)

datafile = serialize_data(public_key, data)
with open('data.json', 'w') as file:
    json.dump(datafile, file)
print("Encrypted Data:", datafile)

answer_file = load_answer()
answer_key = (answer_file['public_key']['n'], answer_file['public_key']['g'])
ciphertext = answer_file['values'][0]

if answer_key == public_key:
    decrypted_answer = decrypt(private_key, public_key, ciphertext)
    print("Decrypted Answer:", decrypted_answer)
