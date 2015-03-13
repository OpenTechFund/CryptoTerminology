# Crypto Terminology

The purpose of this document is not to rigidly define terms for some sort of 'official' use, but rather to serve as an introduction and collective reference to the way terms are commonly used. People will disagree with some of these definitions, and that disagreement is a secondary concern to guiding newcomers to several definitions and giving them the ability to discern which is meant based on context.

This document is not meant to serve as an _introduction_ to cryptography in general, but rather to supplement such guided tutorials and discussions where one is finding unfamiliar terms. If one isn't starting from the very, very beginning (e.g. arithmetic) and encounters a new term - this document should help them understand the term.


## Basics

Integrity - Refers to the consistency of data, in the sense that it cannot be modified in an unauthorized or stealthy fashion.

Confidentiality - The property that data is unreadable by unauthorized parties.

Authenticity - The property that all parties involved in the communication are who they claim to be. 


Symmetric Cipher or Secret Key Cryptography - Cryptography algorithms which use the same key for decryption and encryption. These algorithms are typically based on performing complex rearrangements and XORs of the input bytes, which could be imagined partially as shuffling a deck of cards.

Asymmetric Cipher or Public Key Cryptography - Cryptography algorithms which use one key for encryption (public key) and a different, related key for decryption (private key). Unlike Symmetric algorithms, these algorithms are typically based on underlying mathematical properties that provide a 'trapdoor'. A mathematical operation that is easy to compute in one direction, but difficult to undo - unless one has a secret value that unlocks the 'trapdoor'. 


Plaintext - plain, unencrypted data

Cipher - An Encryption and/or Decryption algorithm

Ciphertext - the result of plaintext encrypted by a cipher


Block Cipher - a cipher which operates on a fixed-size number of bytes, also known as blocks. Plaintext that is not divisible evenly by the block size must be padded before encryption.   

Block Size - The size of the data that a block cipher operates on.  A common block size is 16 bytes or 128 bits. Older block ciphers use a block size of 8 bytes/64 bits.


Stream Cipher -  a cipher which operates by combining (XORing) plaintext with a pseudorandom stream of digits (keystream). As opposed to block ciphers, stream ciphers encrypt one plaintext bit at a time with the corresponding bit of the keystream.


Block Cipher Mode - As a block cipher only encrypts a fixed size block at a time, any data larger than that block size must be encrypted by multiple calls of the block cipher.  A block cipher mode is a specification for how those multiple ciphertext blocks combine, are XOR-ed together, or otherwise interact. (If at all) 


Hash Function - an algorithm that (commonly) accepts a variable-length input and produces a fixed-length output, such that the output is randomly distributed from the input.  A Cryptographic Hash Function performs the same operation, but (at a minimum) also makes it difficult to find two inputs that produce the same output. See also Preimage Attacks.

MAC (Message Authentication Code) - A technique to provide integrity of a message. A MAC creates a small tag from an input to be authenticated (e.g. "Meet me at the park at 12PM") and a secret key known only to the sender and receiver. A recipient can recalculate the MAC over the input, compared with the transmitted MAC, and be assured the message has not been modified by anyone who does not known the secret key.  Not that MAC is a generic term, and while HMAC (Hashed Message Authentication Code) is the most common, other types of MACs (UMAC, CMAC, etc) exist.


Signature - A technique for verifying the authenticity and integrity of a message. A sender computes a signature over a message, and a recipient is able to verify the signature, asserting that the message came from the sender and was not modified.


Key Exchange (sometimes abbreviated 'kex') - A method by which cryptographic keys are either exchanged, or agreed upon, in order to allow the use of a further encrypted communication.


0RTT, 1RTT, 2RTT - Relates to a protocol's round-trip time, or the number of round trips necessary for two parties to begin communicating. 0-RTT means the client can send data in the very first message to the server, and the server can immediately send data after processing the client's first message. 0-RTT makes it very difficult to implement protections such as forward secrecy and replay protection in 0-RTT. 

1-RTT  means the client sends a 'Hello' packet, the server replies, and the Client is able to send data.  1-RTT and above mean more message exchanges are necessary before parties can communicate securely. Fewer round-trips are desired for better performance. TLS 1.2 and below are 2-RTT, although a Session Resumption is 1-RTT.  TLS False Start was a modification to TLS behavior to achieve 1-RTT even on an initial connection. 


Entropy - A difficult term to define, usually meaning randomness. An Operating System collects 'entropy' to be able to securely generate cryptographic keys and similar values.  Passwords often are estimated to have a certain amount of 'entropy' (although these estimations often make wild assumptions.)


Random Number Generator - a system designed to produce a sequence of numbers that appear random i.e. lacking a discernible pattern

PRNG - pseudorandom number generator, an algorithm for generating number sequences that are an approximation of random number sequences. PRNGs generate sequences based on initial values called seeds, which may be random

CSPRNG - cryptographically secure pseudorandom number generator, a prng suitable for use in cryptography. csprngs use high quality sources for entropy and withstand common cryptanalysis tests.



Session - An active communication channel between two parties. A session is established upon a successful exchange of necessary parameters to begin communicating securely.

Padding - Refers to adding meaningless bytes to plaintext in order to extend its length. This may be done to make it a required size (such as matching a block size) or to obscure the length of the underlying plaintext.


Snakeoil - Slang used to refer to a cryptographic protocol or product (usually be sold for a profit) that is advertised as being "secure", "unbreakable", often using "cutting edge techniques no one else is using", advertising wildly impracticable or meaningless key lengths, or touting "military grade". Usually there is little technical information available, and what little there is contradicts all known cryptographic best practice and doesn't make sense. 


MITM (Man in the Middle) - refers to a situation where an attacker can position themself such that they can alter and inject messages in a session. A common communication graph is Alice communicating with Bob (Alice <-----> Bob) - here a MITM (often dubbed "Mallory") impersonates Bob to Alice and Alice to Bob: (Alice <---> Mallory <---> Bob)


## Math

Prime - a number greater than one that has no divisors other than 1 and itself. (2 is counted as prime.) Other examples: 5, 7, 11, 13 Common public key cryptography algorithms are based on large prime numbers.

Semiprime - A product of two prime numbers, e.g. 35 (7 * 5)

Primality Test - An algorithm for determining whether a number is prime. Several primality methods exist with varying complexity and running times.

Group - A set of elements and a mathematical operation that combines any two elements in the set to satisfy properties of closure, associativity, the identity and the inverse properties.  Groups are used in many Public Key Algorithms.

Field - An algebraic structure that builds on a Group, in which every non-zero element has multiplicative and commutative inverses and whose basic operations follow the distributive law.  Fields are likewise used in many Public Key Algorithms.


curves - A mapping of a series of points in space. Most commonly, curves are defined as the output of a simple equation mapping an x-coordinate to one or more y-coordinates in 2-dimensional Euclidian space. Just as Groups are needed in other cryptosystems, a curve is an underlying construct needed in Elliptic Curve Cryptography.  


ECC - Elliptic Curve Cryptography. A form of public-key encryption that uses algebraic curves (of the form y^2 = x^3 + ax + b) as the basis for its underlying mathematics (as contrasted with RSA, which uses very large prime numbers). The security of ECC depends on a series of consecutive "point multiplication" steps, which are easy to describe graphically and compute mathematically, but which as a set is very difficult to "run backwards" to determine the starting point.


Round (in the sense of 20 rounds for AES) - A set of operations that perform part of a symmetric encryption step.  Symmetric Algorithms are often composed of 5, 10, 20 or more 'rounds' of operations. Individuals seeking to demonstrate an algorithm is weak will often begin attacking it on reduced-Round variants (e.g. an algorithm that only performs 10 of the recommended 15 rounds.) These attacks may then be improved to the full-round variant.


Merkle-Damgard - a generic construction of collision resistant hash functions. It composed collision resistant one-way compression functions to produce a complete algorithm. MD5, SHA1, and SHA2 are stuctured as a Merkle-Damgard construction.


Substitution-Permutation Network or SPN - A series of mathematical operations in a block cipher that forms the basis of the cipher's encryption operation. Individual steps, or rounds, either substitute (exchange one value for another) or permute (re-arranges all the bits in the value) the data being encrypted. The actual substitutions and permutations are derived deterministically from the cipher key. The final ciphertext output by the system is the result of this series of rounds.


Confusion - One of the key cryptographic principles described by Claude Shannon in 1949. Confusion holds that every character output by a cryptographic function should depend upon several parts of the key. 

Diffusion - Another of the key cryptographic principles described by Claude Shannon in 1949. Diffusion holds that a change to a single character in the input of a cryptographic function should affect several characters in the function's output.




S-Box - A one-to-one mapping, for a substitution round in a block cipher, which substitutes one block of bits for another block of bits. A strong S-Box will have an "avalanche" effect, in that changing a single bit of the input will cause about half of the output bits to change.

P-Box - A one-to-one mapping, for a permutation round in a block cipher, which widely redistributes input bit values across the entire output value. Generally used in conjunction with an S-Box, a well-designed P-Box will ensure that input bits (output from a single previous S-Box) will be distributed to as many following S-Boxes as possible.



Smooth Number - An integer which can be factored completely into small prime numbers. Smooth numbers can be useful in fast Fourier Transform (FFT) algorithms by recursively breaking problems down into smaller problems based on prime factors.

Square and Multiply - A method of "exponentiating by squaring" that allows for fact computation of very large powers of a number. Multiple optimized algorithms exist to implement these methods, each with varying complexity and computing requirements. 

CRT - The Chinese Remainder Theorem.  A mathematical procedure, used to find specific relationships between an arbitrary number, certain divisors, and certain desired remainders. It can be used for secret sharing (in which a secret can be recovered only if all distributed secrets are collected together) and also for improving the speed of RSA calculations. It can also be used in an attack against RSA, where an identical plaintext is encrypted by a number of different public keys, where that number is larger than the exponent used in the RSA calculations.


Edwards Curves - Another family of elliptic curves (much like the Weierstrass curves y^2 = x^3 + ax + b). Defined as x^2 + y^2 = c^2(1 + dx^2y^2), where c,d are in the finite field K and d is not a square. These curves are isomorphic (a surjective one-to-one mapping exists between points on the curve) to Weierstrass curves. While Weierstrass and Montgomery forms are not complete, meaning there exist special edge cases for addition and doubling formulas (zeros in denominators) which must be accounted for, Edwards curves are complete. Because of the completeness, the addition laws can be used to double a point and thus simplify side-channel mitigations.

Montgomery Curves - Another family of elliptic curves (much like the Weierstrass curves y^2 = x^3 + ax + b). Defined as by^2 = x^3 + ax^2 + x, where a,b are in the finite field K. These curves are isomorphic (a surjective one-to-one mapping exists between points on the curve) to Weierstrass curves. Scalar multiplication on montgomery curves is typically faster than on Weierstrass curves.


Twists - All elliptic curves have another elliptic curve, called the twist, which is isomorphic to the original curve (over the field extension K(sqrt(d), not K). For Weierstrass curves, the twist will look like dy^2 = x^3 + ax + b and any q = x^3 + ax + b which is not square, is on the twisted curve. Scalar multiplication using the Montgomery ladder will compute multiplications on both the normal and twisted curves; This means any attacker may perform invalid-curve attacks using points from either curve.

Point Compression - A method by which individual points on elliptic curves are represented only by their x-coordinate and a sign bit. This has the effect of reducing a public key to nearly half the size as if it had been represented with both x and y coordinates.


Birthday Problem or Birthday Paradox - A paradox arising in probability theory that describes the likelihood that any two members of a random set will be be identical. Generally described as the probability that any two people in a random group will share the same birthday. This likelihood reaches 50% in a group of 23 people, and 99.9% with only 70 people.


P vs NP - Relates to a major unsolved computer science problem. P represents the set of problems that can be solved in polynomial time, where "polynomial time" represents a feasible amount of computer time. NP represents the set of problems that can be verified in polynomial time, but are not believed to be solvable in polynomial time. Cryptography relies on the assumption that P does not equal NP. If the opposite were to be proved, it would mean that many cryptosystems could trivially be broken.  


Factoring - Decomposing a number into its prime divisors. For example: 35 factors to 5 x 7, 20 factors to 2 x 2 x 5.  Many public key cryptosystems rely on the difficulty of factorization of very large semiprimes.

RSA Problem - Determining an RSA private key using only the public key. The security of large RSA keys derives primarily from this process being highly inefficient. This is related to, but not identical to factoring.  It may be possible to solve the RSA Problem without demonstrating an easy method for factoring. (But unlikely.)


Discrete Log - an integer c which solves a^c = b. No efficient method to compute discrete logs exists, and as a result several important public key cryptosystems rely on the intractability of this problem.

Diffie-Hellmann Problem - The mathematical basis for the Diffie-Hellmann key exchange, the Diffie-Hellmann Problem (DHP) is based on the prospect that it is computationally very difficult to compute g^xy while knowing only g^x and g^y, but not knowing g, x, or y. Just as the RSA Problem and Factoring are related, so too are the Diffie-Hellmann Problem and Discrete Log problems.  


Elliptic Curve Discrete Log Problem - Given a point B on a curve that equals a given point A point-multiplied with a constant c, determining the value of c. As with integer-based Siscrete Logs, no efficient method to compute elliptic curve discrete logs exists, and as a result ECC relies on the intractability of this problem.


Lattice Cryptography - Asymmetric cryptography methods using lattices, rather than primes or elliptic curves, as their basis. Some lattice-based systems appear to be resistant to both classical and quantum computer attacks.

Learning With Errors - A problem that is analogous to several Lattice Problems, and thus forms the basis of cryptosystems that aim to resist quantum computing attacks.


Quantum Computing - The use of computers that uses quantum phenomena to perform operations. The advent of quantum computers has significant implications in the cryptanalysis of many important cryptosystems.

Grover's Algorithm - A Quantum Algorithm that attacks symmetric ciphers. If effectively halfs the key length, so AES-128 becomes AES-64, and AES-256 becomes AES-128.

Post-Quantum Cryptography - The study and development of new cryptographic algorithms which are resistant to attacks using quantum computing.


Nothing Up My Sleeve Number - Refers to numbers which are used in cryptography to prove that constants were not selected with the purpose to create a weakness that could later be used as a backdoor.  Often mathematical constants such as e, pi, or sqrt(2) are used.


N - widely used as the public modulus in RSA. n = p*q

p,q - widely used to denote primes. When p is singular, often used as the exponent for a Discrete Log-based algorithm. When p and q are together, often used to denote the secret primes that compose an RSA private key

e,d - widely used to denote the public (e) and private (d) exponents used in RSA

q, qinv - widely used to denote elements used in RSA. The value q is one of the secret primes that comprise the RSA key, and qinv is the modular multiplicative inverse of q.

a,b - when used with g, are often used to denote the secret exponents of two parties performing Diffie-Hellman.  a is Alice's secret value, g^a her public. b is Bob's secret value, g^b his public.

g - widely used to denote the generator of a group



## Algorithms and Algorithm Properties

One Time Pad - A technique in which the plaintext is paired with a secret random key (pad) using modular addition. If the key is random, as long as the plaintext, never reused, and is protected sufficiently from disclosure, then the ciphertext is impossible to decrypt. Steam ciphers are a rough approximation of a one time pad.

RSA - a widely used public-key cryptosystem in which the public key is distributed and the private key is kept secret. Its security is derived from the difficulty in factoring the product of two large prime numbers. It stands for Rivest, Shamir, and Adleman, the authors of the algorithm.  It is also the name of a company that licensed RSA and other cryptography related products.

PKCS (Public Key Cryptography Standards) - A family of standards published by RSA in the 1990s to attempt to standardize a number of different things relating to Public Key Cryptography. This includes padding algorithms for RSA, to file formats for transporting public and private keys, to APIs used to communicate with smart cards.


PKCS1v1.5 -  A particular type of padding for RSA Encryption and Signatures, named after the document in which it appears. It is old, known to be vulnerable to chosen ciphertext attacks, most notably Bleichenbacher's attack, and not well regarded in the cryptographic community.  However, it is very simple to implement and understand, and sees continual use and deployment through industry protocols, to the consternation of many.

OAEP (Optimal Asymmetric Encryption Padding) - The generally recommended form of padding for RSA Encryption, although its significantly more complex than PKCS1v1.5 padding. It was standardized in PKCS1v2.

RSA-PSS - The padding scheme for RSA Signatures that complements OAEP.


Rabin - An asymmetric cryptography cryptosystem, similar to RSA in that it relies on large coprime factorization. It is believed to be more secure than RSA in the sense that it is proven to be as hard as integer factorization (something which is yet to be proven for RSA), but is proven to be breakable via chosen ciphertext attacks.  

DH or Diffie-Hellman - A method of agreeing on a secret key over a public channel. It is vulnerable to a Man-In-The-Middle impersonating the parties to each other.

ElGamal - An asymmetric encryption algorithm based on DH. It's mostly known for being widely used in older versions of PGP and GPG.

ECC - A catch-all term for public key crypto algorithms based on elliptic curves. As opposed to RSA which depends on large prime numbers, ECC derives its security from the difficulty of finding discrete logarithms of a curve given original and product points. It is believed that the bit size of keys in ECC offer about twice the security compared to RSA keys. In other words, with ECC the same level of security is obtained with smaller keys, resulting in increased performance at no (currently known) security cost.

ECDH - A variant of the Diffie-Hellman key agreement using elliptic curves.

ECDSA - A variant of the digital signature algorithm using elliptic curves.

ECIES - A variant of the Integrated Encryption Scheme for ECC. Like EIC, it provides security against attackers who can used chosen plaintext and chosen ciphertext attacks.


NTRU - A patented, open source public key cryptosystem that uses lattice-based cryptography. Compared to RSA, it performs private key operations significantly faster at an equivalent strength, while increasing strength significantly faster than RSA with increasing key sizes, and is currently not known to be vulnerable to quantum computer based attacks. Due to these benefits it has seen a recent increase in popularity.


PBKDF (Password-based Key Derivation Function) - A method of 'stretching' a lower-entropy password into a cryptographic key. Using these for actual cryptographic keys is not recommended without careful review. They are most commonly used for storing one-way hashes of passwords, to make brute-force guessing slower.

PBKDF or PBKDF2 (specifically referring to the PBKDF2 standard) - a popular key derivation function which applies a cryptographic hash, cipher, or HMAC to a passphrase with a salt and repeats the process several times to derive a key that can then be used a cryptographic key. It was designed to make password cracking difficult as it is a computationally expensive operation and the salt protects it against rainbow table attacks. It allows the number of times to be adjusted to account for constantly increasing computational power. PBKDF2 specifically is weak to brute-force attacks using ASICs or GPUs due to its very small circuitry and memory requirements.

Bcrypt - A PBKDF based on the Blowfish cipher commonly used in BSD systems. Compared to PBKDF2, bcrypt requires more memory and is slightly stronger against ASIC and GPU based brute forcing. 

Scrypt -  A more modern PBKDF specifically designed to resist hardware attacks by requiring arbitrarily large amounts of memory. scrypt-based proof-of-work schemes are currently used by Litecoin and other cryptocurrencies. 

Password Hashing Competition - An ongoing (as of early 2015) competition to design a new password hashing algorithm to potentially replace bcrypt, scrypt, and PBKDF2.  https://password-hashing.net/



MD2 - Message Digest 2, a cryptographic hash function, the first in the MD series. It is no longer considered secure as attacks are relatively low complexity.

MD4 - A successor to MD2, considered severely broken. Used by NTLM on Windows up to Windows 7 as well as older versions of rsync.

MD5 - A widely used successor to MD4, commonly used for data integrity and password hashing despite being considered broken and not suitable for crypto purposes. 

MD6 - A hash function submitted to the SHA-3 competition, but withdrawn before potential selection. Unlike its predecessors, whose hash size was 128 bits, MD6 uses variable-sized digest sizes up to 512 bits. It offers significantly higher performance than MD5. It has seen little use and was known for having a buffer overflow in its reference implementation as well as its first known production use being in the Conficker worm. 


SHA-0 - The original Secure Hash Algorithm. It was retired shortly after it was published due to collision attacks - attacks which have significantly improved over the years.

SHA-1 - A popular hash function designed by the NSA to be used for DSA. Though similar to MD5, it's a 160 bit hash function. It's no longer approved for cryptographic use due to discovered weaknesses.

SHA-2 - A family of two hash functions designed by NSA. The two functions, SHA-256 and SHA-512 differ in block and word sizes (32-bit and 64-bit words respectively).

SHA-256 - The SHA-2 hash function using a 32-bit block size and returning a hash which is 256 bits in length.

SHA-512 - The SHA-2 hash function using a 64-bit block size and returning a hash which is 512 bits in length.

SHA-224 - truncated version of SHA-256 to 224 bits

SHA-384 - truncated version of SHA-512 to 384 bits

SHA-512/256 - Truncated version of SHA-512, with an initial value generated using a method defined in FIPS PUB 180-4.

SHA-3 Competition - A competition run by NIST to select the successor to SHA-2

Keccak - The hash function that won the SHA-3 competition.

TIGER, WHIRLPOOL, - Other hash functions, used less commonly



HMAC - a method for calculating a MAC using a cryptographic hash function and a secret key.

UMAC - a type of MAC calculated with by choosing a hash from a set of hash functions using a random selection method, applying it to the input, and then encrypting it to prevent fingerprinting the hash method used. Typically, it's significantly less computationally intensive than other MACs. 

CMAC - a MAC based on a block cipher. AES based CMAC is used for IPSec


RC4 (arc4, arcfour) - the most widely used stream cipher, used in TLS and WEP. Despite its performance, it is vulnerable to many attacks and is expected to be completely broken in the near future, and therefore unsuitable for crypto.

Salsa - A family of stream ciphers from which Salsa20 is most notable.

ChaCha - A family of stream ciphers related to Salsa20, selected by many in the community as the replacement for RC4. Coming soon to TLS.

eSTREAM - A project run between 2004 and 2008 to identify new, high-security stream ciphers. The eSTREAM Portfolio consists of HC-128, Rabbit, Salsa20, and SOSEMANUK



AES Competition, AES Finalists - A public standards selection process run by NIST from 1997 - 2000, to select a new standard encryption algorithm which would become known as AES. Fifteen cipher designs were submitted. In August 1999, the list was reduced to 5 finalists (Rijndael, Serpent, Twofish, RC6, and MARS).

Rijdael - The cipher which won the AES competition, selected by the NIST AES Competition in October 2000.

AES - The most predominant symmetric key encryption algorithm, and the first publicly accessible cipher approved by the NSA for protection of top secret information. It uses key sizes of 128, 192, or 256 bits. 



DES - A symmetric key algorithm that was once widely used. It's keysize (56 bits) is much too low to be considered secure today, but aside from brute-force attacks as stood up ell against cryptanalysis. 

TDES or Triple DES - A symmetric key block cipher which applies DES 3 times to each block. This increases the keysize to acceptable levels. Attacks exists for Triple DES, though they are currently considered not practical. It is very commonly used by the electronic payment industry, but not very common elsewhere. It is also notable for being the only widely used cipher today with a 64-bit block size.

Camellia - A 128 bit block cipher standardized in Japan, and present in TLS. 

SEED - A block cipher developed by the Korean Information Security Agency. Though initially unsupported by major libraries and web browsers, it is now supported by TLS, S/MIME, IPSec, among others. It is commonly used in South Korea, but rarely elsewhere. 

CAST-5 - a symmetric key block cipher known for being the default cipher in certain GPG/PGP versions.


Ciphertext Stealing - A technique occasionally used in cipher block modes that allows the length of the ciphertext toexactly match the plaintext, even if it is not a multiple of the block size. 

ECB Mode - The simplest of encryption modes for block ciphers. In ECB, each block is encrypted separately, as a result, identical plaintext blocks result in the same ciphertext, revealing patterns in the ciphertext. As a result, it does not complete confidentiality and is not recommended for cryptographic use. 

CBC Mode - A mode in which each block of plaintext is XORed with the previous ciphertext block before being encrypted. The first block is used with an initialization vector.

CTR Mode - A block mode which encrypts a block cipher as a stream cipher by encrypting each block with any function which does not repeat for a long time, though an incrementing counter is the most used. It allows blocks to be encrypted in parallel, and therefore benefits from multi processor machines.

CFB Mode - Similar to CBC in operation, except it encrypts as if it was a stream cipher by treating the previous block as the keystream. 

OpenPGP CFB Mode - A variant of CFB which is used by OpenPGP. It is known to be vulnerable to adaptive chosen ciphertext attacks.


AEAD Modes - authenticated block cipher modes of encryption which encrypt and authenticate blocks simultaneously, such as OCB, CCM, GCM modes. 

GCM Mode - A high performance and widely adopted block cipher mode which combines CTR mode with Galois authentication.

CCM Mode - An authenticated block cipher mode which combines CTR mode with CBC-MAC. It is used in the CCMP encryption algorithm for WPA2 as well as IPSec and TLS 1.2.

OCB Mode - A minimal authenticated cipher block mode which integrates a MAC into the block cipher, avoiding the use of different methods for encryption and MAC, and therefore reducing computational cost.


Disk Encryption Modes - Block cipher modes suited for disk encryption. Block cipher modes which operate as stream ciphers are unsuitable as they require extra disk space to store initial states, and modes such as (plain) CBC and ECB can leave discernible patterns on disks as sectors are encrypted separately.

ESSIV - a method for generating IVs suitable for use with CBC for disk encryption. ESSIV prevents issues in plain CBC by generating IVs from a combination of the sector number with the hash of the key, making the IV unpredictable. It is a common option used in dm-crypt based disk encryption on Linux.

XEX - An encryption mode for full disk encryption in which an "XOR-Encrypt-XOR" pattern is followed. The disk sector address is used as input to a function to compute X. X is then XORed with the plaintext, the result encrypted, and then the result of that encryption again XORed with X.

XTS - A XEX based mode which uses ciphertext stealing. Due to a misinterpretation of the original paper describing XEX, XTS sploits the block cipher's key in half, increasing complexity without any security benefit e.g. AES256 requires a keysize of 512 bits. It is the most widely supported disk encryption mode, used by OS X File Vault 2.

Elephant Diffuser - A permutation algorithm that was used in older versions of Windows’ Bitlocker. Elephant was unkeyed, and served only to cause a small bit change to propagate to a bunch wider range of ciphertext than it would ordinarily be. This provided a form of ‘poor-man’s authentication’.


Gost - Refers to a suite of algorithms defined by the Russian government. Gost is often used as a single term, but technically refers to a suite of functions.  There is a GOST block cipher, a GOST ECC-based signature algorithm, and a GOST hash function.

25519 - A widely-used elliptic curve, adopted as an IETF standard in 2015.

Goldilocks - A set of curves put forward by Mike Hamburg at higher security levels than 25519

NUMS - A set of curves put forward by Microsoft in mid-2014

BADA55 - A set of elliptic curves with a "verifiably random" seed which was non-randomly tweaked to include the string "BADA55". Generated to highlight a possible weakness in believing the randomness of such "nothing up my sleeve" numbers.

P-Curves - A set of elliptic curve parameters based on prime curves standardized by NIST, based on pseudo-Mersenne primes.

K-Curves - A set of elliptic curve parameters based on binary field standardized by NIST, based on pseudo-Mersenne primes.  While binary curve-based algorithms are faster in hardware, they are often avoided due to mathematical hunches that their structure may enable additional attacks. 

NIST - The National Institute of Standards and Technology, a US Government agency which is responsible for developing and promoting cryptographic standards.



Constant Time - Algorithms which are designed to require the same amount of time to execute regardless of the input conditions. Algorithms which do not execute in constant time may leak information to an attacker and permit attacks against the system.

Data-Dependent Branches - Elements of a program, the execution of which is dependent upon the data being processed. May permit side-channel attacks, if the branches leak information to an attacker (such as differences in execution time or power consumption).

Cache-Neutral - Algorithms which are designed to access any caches (such as RAM or CPU Caches) based solely on public data. The opposite, accessing caches based on (e.g.) a private key, leads to side channel attacks such as differences in execution times, power consumption, or manipulation of shared caches accessible to an attacker.  


N-of-M - A threshold scheme, whereby a secret may be decrypted by using a subset N of a total, larger set of M different keys.


IND-CPA - Indistinguishability under Chosen Plaintext Attack. The principle that an attacker, submitting two different plaintext messages, cannot distinguish which of the two messages was randomly encrypted by a given secret key. A cipher which does not allow for distinguishability better than random chance is said to possess IND-CPA.

IND-CCA - Indistinguishability under Chosen Ciphertext Attack. A test, similar to IND-CPA, in which an attacker has the opportunity to submit arbitrary ciphertexts to a decryption oracle, in order to improve the possibility of discovering an advantage in an IND-CPA test.   

IND-CCA2 - An adaptive variant of the IND-CCA test, in which the attacker may continue to submit arbitrary calls to the decryption oracle in order to further improve the ability to distinguish between two randomly selected ciphertexts. 

INT-CTXT - A requirement that it be computationally infeasible for an attacker to produce a valid ciphertext not previously produced by the sender. 

INT-PTXT - A requirement that it be computationally infeasible for an attacker to produce a valid ciphertext which decrypts to a message which the sender never encrypted. 


Suite A - A set of cryptographic tools and algorithms in use by the United States National Security Agency (NSA), containing classified algorithms that "will not be released." These algorithms are implemented in "Type 1" products, used by the U.S. to protect classified information.

Suite B - A set of cryptographic tools and algorithms published by the NSA and freely available for public use. Suite B includes AES-128 / 256, ECDSA, ECDH, and SHA2. 

Zero-Knowledge - - A Zero Knowledge Proof is a method by which a statement is proven to be true without imparting any information to the recipient of the proof, other than that the statement is true. Colloquially, Zero-Knowledge is often used to describe a product or system which claims not to be able to decrypt the user's data when it is encrypted with a user-managed key. For example, a client application which encrypts backups before sending them to a server.  This is not in any way related to the mathematical definition. 


Homomorphic Encryption - A form of encryption that allows computations to be performed on the ciphertext, without first decrypting the text.

Searchable Symmetric Encryption - An encryption system that allows a user to search the ciphertext for a fragment of data without actually decrypting the ciphertext. For example, a system that permits the identification of an encrypted record which contains a given plaintext Social Security Number.

Deniable Encryption - An encryption technique in which it is impossible to prove that a string of data is an encrypted message without possession of the encryption key.

Repudiation - Successfully challenging the validity of a statement. Non-repudiation can be provided by use of a digital signature, which proves that the signer did issue the signed statement (provided the private key has not been compromised.) 

Group Signature - A system whereby a member of a defined group can anonymously sign a message on behalf of that group.

Identity-Based Cryptosystem - Public key cryptography in which an identifier (such as an email address) is used as a public key. IBE systems use a centralized method to generate private (and public) keys for the identifier. This centralization may be seen as a point of vulnerability or a feature depending on your vantage point.


## Attacks

Oracle - An oracle is something that tells you something about something.  Different types of oracles specify those terms more concretely:

Error Oracle - An error oracle leaks information about 'something' in the form of a different error message depending on input. For example, one input may give an error of 'Incorrect Parameter', another 'Invalid Parameter'. The different of these errors indicates in what part of the code the input was rejected.

Timing Oracle - A Timing Oracle leaks information about 'something' in the form of faster or slower operations. Timing oracles can be used to e.g. determine if a parameter was rejected as invalid early in the processing code or later.

Padding Oracle - A Padding oracle leaks information about whether or not the padding was invalid. The exact way this is exposed may be by an Error Oracle, a Timing Oracle, or other.  Padding Oracles are used, e.g., to attack CBC Mode, PKCS1v1.5 (Bleichenbacker), and OAEP (Manger's)


Time/Memory Tradeoff - A method of exploiting a tradeoff between long-running computations and storage. In many cases, time of computation can be reduced at the cost of increased memory usage and vice versa. 

Rainbow Table - A precomputed table for cracking password hashes. It applies time/memory tradeoff by reducing computational time to reverse a hash function at the expense of large memory requirements.


Known Plaintext (KPA) - An attack on cryptographic algorithms where the adversary has one or more samples of plaintext and their encrypted ciphertexts.

Known Ciphertext (COA) - Also known as Ciphertext Only Attack, an approach where the attacker only knows the ciphertext and nothing else.

Chosen Plaintext (CPA) - An attack on cryptographic algorithms where the adversary has one or more samples of plaintext and their encrypted ciphertexts and is able to choose them. 

Chosen Ciphertext (CCA) - An attack where the attacker is able to submit arbitrary ciphertexts to the system and receive the resulting plaintexts, to attempt to recover the secret key.

Adaptive Chosen Ciphertext Attack (CCA2) - An attacker is able to adaptively submit chiphertexts to the decryption system both before and after a challenge ciphertext has been received.


Encryption Oracle - A service which permits someone to submit arbitrary plaintexts and receive the appropriate encrypted ciphertexts.

Decryption Oracle - A service which permits someone to submit arbitrary ciphertexts and receive the appropriate decrypted plaintexts. This is often used in the phrasing of an attack, such as "By exploiting this vulnerability, you create a Decryption Oracle."

Signing Oracle - A service which permits an attacker to submit arbitrary messages and receive a valid signature, signed using the service's private key.


Key-Recovery Attack - An attack on an encryption service which results in the recovery of the secret key.

Message Forgery - A message where the apparent sender of the message is forged, such that the recipient believes it came from the forged entity. 

Replay Attack - An attack where valid data is captured and replayed to maquerade data sent by a legitimate party.

Password Cracking - Recovering a password by use of a dictionary or brute force attack.


Bleichenbacher - A swiss cryptographer, who has demonstrated attacks against RSA using PKCS#1 padding, as well as "pencil and paper" attacks against RSA signature validation. Often commonly used to refer to the Adaptive Chosen Ciphertext Attack on PKCS#1 v 1.5 Padding.

OAEP Attack or Manger's Oracle - An attack, similar to Padding Oracle, against Optimal Asymmetric Encryption Padding used in PKCS#1 v2.0.


Coppersmith's Low Exponent Attack - A direct attack against RSA ciphertexts where the public RSA exponent is small, commonly e=3. 

Small Subgroup Attack - An attack on public key systems that fail to validate peer public keys. By forcing derived secrets into small subgroups, an attacker can recover peer private keys or violate contributory assumptions of some protocols.

Brute Force - The most inefficient and trivial kind of attack. It consists of systematically checking all possible passwords or keys until the correct one is found.

Reduced Round - An attack against a cipher system which has been modified to use fewer than expected rounds. Though the attack may not lead directly to success against the full cipher algorithm, understanding of the reduced-round vulnerabilities may lead to breaks against the complete system. 

Slide Attack - A form of cryptanalysis which exploits weaknesses in the schedule of (in particular) cyclicly-repeating ciphers.

Boomerang Attack - A differential cryptanalysis attack which has proven useful against many ciphers otherwise believed to be safe from differential cryptanalysis.

Meet in the Middle Attack - An attack, making use of known pairs of plaintexts and ciphertexts, especially against cryptosystems which use successive encryptions steps each with separate keys.

Linear Cryptanalysis - An attack using linear equations which relate plaintext, ciphertext, and key bits, then uses that system of equations with known plaintext / ciphertext pairs to derive some or all of the key.

Differential Cryptanalysis - An attack which measures how small changes in an input can result the output of a cryptographic function, to attempt to derive the secret key.

Impossible Differential - A form of differential cryptanalysis which exploits differences in intermediate cipher states which are impossible.

Biclique Attack - A variant of meet-in-the-middle attack, which can extend the number of rounds attacked. Bicliques are the best publicly-known attack against AES, but still require significantly high amounts of work. Biclique attacks exist for many ciphers that reduce the security by one or two bits.

Related Key Attack - An attack where the attacker can observe a cipher using several different keys which are unknown, but mathematically related in a way known to the attacker.

Block-Swapping - Moving one or more blocks in a ciphertext to other locations in the ciphertext, to cause a predictable change in the plaintext. Most commonly used against ECB Mode.

Bit-Flipping - Changing the state of one or more bits in a ciphertext to cause a predictable change in the plaintext.

Replay Attack - Presenting a message a second time to attempt to (potentially) elicit the same behavior from a system.


Collision Attack - An attack on cryptographic hash functions which attempts to find any two inputs which produce the same hash.

Preimage - An attack against a hash function whereby the attacker attempts to find a message with a specific hash value.

Second Preimage - An attack against a hash function whereby the attacker attempts to find a message with the same hash value as a given message.

Chosen Prefix - A hash collision attack, where an attacker chooses two _suffixes_ that, given a specific _prefix_ result in the same hash value. Chosen Prefix attacks have been used to attack signatures based on MD5.

Length Extension - Given a hash function H an output C, and an unknown input M, choosing an input M' and producing a new output C' such that H(M|M') = C'  Length Extension attacks can be used to defeat MD5, SHA-1, and SHA-2 hash functions when they are used to protect a secret prefix. The appropriate construction to use in this case is HMAC.


GNFS or General Number Field Sieve - An algorithm for factoring large integers. The GNFS is not efficient for 2048 bit semiprimes

FFS or Function Field Sieve - An algorithm for extracting discrete logarithms. The FFS is not efficient for 2048 bit Discrete Log groups.


BEAST - A successful demonstrated attack against a CBC vulnerability in SSL 3 and TLS 1.0.

CRIME - An attack against TLS sessions with compression enabled that allows recovery of plaintext in the session.

BREACH and TIME - Variants of the CRIME attack which exploit HTTP compression.

Lucky13 - A cryptographic timing attack against TLS.


Power Analysis - A side channel attack that can be used to extract cryptographic keys.

Differential Power Analysis - A power analysis attack performed by statistically analyzing power usage over multiple operations.

TEMPEST - Methods for shielding electronic devices from side-channel attacks utilizing remotely-detectable RF emanations.

Frequency Analysis - Cryptanalysis based on frequency of characters or symbols in a ciphertext.

Traffic Analysis - Analysis of a large number of encrypted messages based on traffic flows -- origins, destinations, sending time, message length, message frequency, etc. Traffic analysis may be able to reveal the meaning of messages even when the messages themselves have not been decrypted.  

Key Logging - The use of malicious hardware or software that logs all of the victim's keystrokes.

Rubber Hose Cryptanalysis - Recovering a secret key (or contents of an encrypted message) by torturing a person with knowledge of the secret information.

## The Crypto Pals

Alice - In conversational explanations of cryptographic principles, the originator of a message (the message goes from A to B).

Bob - In conversational explanations of cryptographic principles, the recipient of a message. Alice and Bob often reply to each other.

Eve - In conversational explanations of cryptographic principles, a (usually passive) eavesdropper on an exchange.

Mallory - In conversational explanations of cryptographic principles, an active, malicious attacker (generally a man-in-the-middle) on an exchange.

Trent - In conversational explanations of cryptographic principles, a trusted third party.

#### Less Commonly Used

Carol - In conversational explanations of cryptographic principles, a third participant in the exchange.

Dan - In conversational explanations of cryptographic principles, a fourth participant in the exchange.

Sam - In conversational explanations of cryptographic principles, usually refers to the government. As in 'Uncle Sam'. In different contexts, Sam may be an attacker or a trusted third party.

Peggy - In conversational explanations of cryptographic principles, a "prover" in zero-knowledge proofs.

Victor - In conversational explanations of cryptographic principles, a "verifier" in zero-knowledge proofs.


## Protocols

Challenge Response - An interactive protocol whereby a challenger sends a challenge to a user (or supplicant), who performs some action or retrieves some item of information, in order to provide a response which proves their identity.

Clocks or Nonces - A tradeoff made in protocols to prove 'freshness' and prevent replays.  Either the protocol participants must have accurate clocks (in which case signed timestamps can prove 'freshness'), or they must provide a nonce which is signed (which prevents replays so long as the nonce is only ever used once.)

Rekeying - Changing a key (usually a session key in an ongoing communication) to reduce vulnerability to cryptanalysis or replay attacks.

Forward Secrecy/Security - The principle that a negotiated session key cannot be compromised even if the long-term key(s) upon which it is based are compromised in the future.

Perfect Forward Secrecy/Security - An additional property onto of Forward Secrecy that preserves the session key even if past session keys are disclosed.  

Future Secrecy - If a Session Key is compromised, a protocol is Future Secret if that compromise does not allow the compromise of future sessions.

All three terms are the subject of debate and colloquial definitions may vary, swapping one property for another.

Self-Healing - Sometimes used as a direct synonym for Future Secrecy. Othertimes, used as a description of a more nuanced property: If Alice and Bob communicate with a session key K, K is stolen by Eve or Mallory, and then Alice and Bob communicate for some time outside of Eve or Mallory's ability to persist compromise - then self-healing may mean the property that Eve or Mallory is now locked out from future decryption or impersonation. The use of the protocol, outside of Eve or Mallory's influence, has 'healed' it against the initial compromise. In the latter use, a protocol may not be Future Secret, but it may be Self-Healing. 


PAKE (Password-authenticated Key Exchange) - An interactive method for generating a cryptographic key based on a given password. In normal PAKE, both parties know the shared password. Refers to the general property, of which there are many protocols. 

SRP (Secure Remote Password protocol) - A specific protocol (which is a PAKE) in which the server does not know the password used to derive the keys. Notable for being defined in TLS, as well as being the subject of debate regarding patents.


Key Agreement Protocol - Any protocol in which two or more parties simultaneously influence the derivation of a shared cryptographic key.

Key Derivation Function (KDF) - Derives one or more secret keys from a secret value. For example, a function which securely expands a shared secret generated by DH into multiple cryptographic keys.


Dining Cryptographers - An amusing party game for cryptographers at a dinner. Also used as the basis for more complicated anonymity systems. https://en.wikipedia.org/wiki/Dining_cryptographers_problem

PIR (Private Information Retrieval protocol) - Allows the retrieval of information from a database without revealing which data was retrieved.

Oblivious Transfer - A protocol where a sender provides a piece of information, but is unaware as to which data was transferred.

OTP (One Time Password) - A general description of a protocol for generating a password which is only valid for a single use, and which if presented a second time will be refused.

TOTP (Time-based One Time Password) - A password which is only valid for a fixed period of time. An IETF standard RFC-6238 defines a specific algorithm for computing TOTP, which is utilized by a number of authentication systems.

HOTP (HMAC-based One Time Password) - A password which is derived from an HMAC operation involving a secret password and some form of nonce or counter.


Timestamp Service - A service which provides a trusted timestamp for a message of other set of data, while not divulging the contents of that data to the service.

TLS - Transport Layer Security, a protocol for secure communication.

TLS-PSK - TLS encryption utilizing a key shared in advance between both ends of the transmission.

TLS-SRP - TLS encryption in which the key is derived using the Secure Remote Password protocol.

TLS-OpenPGP - A protocol for using OpenPGP certificates for TLS sessions.

PKI - Refers to Public Key Infrastructure, the systems necessary to create, manage, and revoke certificates.

X509 - A standard for PKI certificates, including public keys, certificate revocation lists, and certificate validation.

IPSEC - An IP protocol whereby each packet is authenticated and encrypted.

DNSSEC - A system for providing authentication and integrity to DNS records.

DNSCurve - A DNS protocol featuring authenticated and encrypted data transmission between resolvers and authoritative servers.

DNScrypt - A DNS protocol which provides authenticated and encrypted data between end user systems and DNS servers.

DKIM (DomainKeys Identified Mail) - An email validation system used to detect spoofed messages.

PGP (Pretty Good Privacy) - A system of tools, message formats, and encryption standards for public-key based cryptography.

OpenPGP - An open standard for data encryption based on the PGP system.

GPG (Gnu Privacy Guard) - An open-source implementation of the OpenPGP standard.

SMIME (Secure/Multipurpose Internet Mail Extensions) - A standard for the signing and encryption of MIME-formatted data using public keys, usually associated with email clients.

OpenVPN - An open-source VPN system that uses a custom protocol built around TLS.

SSH - Secure Shell, a common remote shell access software used to log in to remote systems and also as basis for secure copy (SCP) and secure FTP (SFTP).

ZRTP (Z + Real Time Transport Protocol) - A key-agreement protocol for VOIP, developed by Phil Zimmerman (the "Z"). Uses Diffie-Hellman and SRTP.	

Onion Routing - A method for anonymous network communication, in messages are encapsulated in multiple layers of encryption, with each subsequent network hop only revealed as the packet passes through the network.

Mix Networks - A method for anonymous network communication, in which several consecutive proxy servers randomly scrambles timing and ordering of multiple message streams to weaken traffic analysis. 

Tor - Free server and client software that implements onion routing on the public Internet.

Bitcoin - A decentralized virtual currency which relies heavily on cryptographic theories to generate and exchange value.

Blockchain - A distributed public ledger of all bitcoin transactions.

SCIMP (Silent Circle Instant Messaging Protocol) - A protocol that layers encryption, authentication, and perfect forward secrecy on instant message systems such as Jabber.

WPA2 - The latest version of Wi-Fi Protected Access, a protocol used to secure mobile wireless networks.

WPS (Wi-Fi Protected Setup) - A protocol to permit simple pushbutton configuration of secure wireless networks. 


## Authentication Models

Pre-Shared Keys - Keys for an encrypted channel shared amongst all participants before establishment of the channel.

TOFU (Trust on First Use) - An assumption that the key received when first establishing a communications channel is legitimate, and trusting that key for future uses, prompting with an error if future communications use a different key. Used by SSH.

Fingerprint Comparison - Comparing a short fingerprint (for example, a hash) of a longer key against fingerprints recorded from previous communications. A mis-match may indicate a changed key or intercepted session.

Certificate Transparency - The monitoring and auditing of public certificates though an open framework.

CT-style (Certificate Transparency-style) Logs or 'Trans' (Transparency) Mechanisms - The notion that public keys are placed in a global, append-only log that allows interested parties to look for the issuance of invalid certificates.  

Network Perspectives or Convergence - Systems which validate a certificate based on the assumption that if the certificate is seen from multiple network perspectives (e.g. Alice in the UK, Bob in Russia, Carol in Japan, and Dan in Mexico) it is valid.

n-of-m Endorsements - A decision to trust information based on some pre-selected majority vote of trusted endorsers.

Web of Trust - A decentralized trust model in which trust is transitively assigned to unknown information based on intermediate endorsements by entities directly trusted (or indirectly trusted, to some possibly definable degree) by the end user. Said another way "If My friend Rob trusts it, I trust it."

Blockchain-Based - Use of blockchain technology, similar to the Bitcoin ledger, for publication, monitoring, and auditing of certificates.

Namecoin - A Bitcoin-derived cryptocurrency that stores and authenticates DNS-like records as part of its blockchain. 

CA (Certificate Authority) - An organization which signs PKI certificates for use in a hierarchical public key trust model. Any certificate with a signature chain which includes (or terminates with) a trusted certificate authority's certificate is, by nature of the chain of trust, trusted by the end client.  Citing the 'CA-model' of authentication usually refers to the notion of having a groups of trusted signers, any of whom can issue a signature for a piece of data.

Federal PKI - A public key infrastructure with root certificates issued and managed by the US Federal Government.

DNSSEC - If DNSSEC is referenced as an authentication model, it usually refers to the notion of a single, central CA with a hierarchy of sub-CAs

DNSSEC-Stapled or 'Include a DNSSEC chain' - Place a key K in DNS (technically this is optional but if you assume they're there, it helps visualize it), and have K signed with DNSSEC. Now take the entire DNSSEC chain of signatures out of DNS, and provide them... somehow. You establish trust in K by following the chain of signatures up to the root DNSSEC key.  Chrome briefly supported authenticating SSL certificates via DNSSEC-stapling.


## Notable Trivia

Clipper - An encryption chipset promoted by the NSA in the early 1990s. The system utilized the Skipjack algorithm, and a mandatory key-escrow policy which would have granted US Federal investigators some access to decrypt clipper-encrypted traffic.

NSA strengthening DES S-Boxes - After IBM submitted the LUCIFER algorithm as a candidate for DES, the NSA reviewed the specifications and made some modifications to keylength and S-Boxes within the algorithm. Some saw this as evidence of tampering to make the cipher easier for NSA to break. Later, after Differential Cryptanalysis was discovered (publicly) it was found that the original S-Boxes were _weaker_ against differential cryptanalysis than the ones the NSA chose.

Crypto Wars - A series of challenges, restrictions, and discussions in the 1990's and early 2000's, focused on US Government restrictions on the development, use, and dissemination of many modern cryptographic technologies. 

Printing out the book for Europe Publication - Attempts to circumvent the application of US munitions export laws regarding cryptographic source code by printing the source code in a book and citing a 1st Amendment defense. This approach was utilized by Phil Zimmerman in 1993 when challenging regulations which restricted the distribution of PGP.

NSA backdooring DUAL_EC - Speculation exists that the NSA deliberately put forward the Dual_EC_DRBG random number generator and generated the public parameters in such a way to allow NSA to break keys generated by that function. The algorithm was known to be slow and possibly insecure soon after publication, but remained available in off-the-shelf software libraries until 2013.
