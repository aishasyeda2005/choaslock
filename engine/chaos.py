"""Chaos generation engine for ChaosLock.

Uses the Logistic Map: x_{k+1} = r * x_k * (1 - x_k).
Provides deterministic derivation of (x0, r) from a user password via SHA-256,
and produces chaotic pseudo-random float sequences.
"""
import hashlib
import numpy as np


def key_from_password(password: str) -> tuple[float, float]:
    """Derive chaotic initial condition x0 and parameter r from a password.

    Algorithm steps:
    1. Compute SHA-256 digest of the password string.
    2. Map the first 8 bytes (64-bit integer) to initial state x0 in (0.1, 0.9).
    3. Map the next 8 bytes (64-bit integer) to growth parameter r in (3.9, 4.0).

    Why this design:
    - SHA-256 provides the avalanche effect: changing even 1 character in the
      password flips ~50% of the digest bits, yielding drastically different
      (x0, r) parameters.
    - x0 is kept strictly within (0.1, 0.9) to avoid the fixed points at 0 and 1.
    - r is kept within (3.9, 4.0) where the Logistic Map is in full chaotic regime
      with a positive Lyapunov exponent.

    Args:
        password: Plaintext password string.

    Returns:
        tuple (x0, r):
            x0 (float): Initial value strictly in (0.1, 0.9).
            r (float): Control parameter strictly in (3.9, 4.0).
    """
    if not password:
        raise ValueError("Password cannot be empty.")

    # Step 1: Hash the password with SHA-256
    digest = hashlib.sha256(password.encode("utf-8")).digest()

    # Step 2: Map first 8 bytes to x0 in (0.1, 0.9)
    # Using 2**64 + 1 ensures the fraction is strictly in (0, 1), so x0 is strictly in (0.1, 0.9)
    int_x0 = int.from_bytes(digest[:8], byteorder="big")
    fraction_x0 = (int_x0 + 1) / (2**64 + 1)
    x0 = 0.1 + 0.8 * fraction_x0

    # Step 3: Map next 8 bytes to r in (3.9, 4.0)
    int_r = int.from_bytes(digest[8:16], byteorder="big")
    fraction_r = (int_r + 1) / (2**64 + 1)
    r = 3.9 + 0.1 * fraction_r

    return float(x0), float(r)


def logistic_sequence(x0: float, r: float, n: int) -> np.ndarray:
    """Generate a sequence of n chaotic values using the Logistic Map.

    Equation: x_{k+1} = r * x_k * (1 - x_k)

    Algorithm steps:
    1. Discard the first 1,000 iterations ('burn-in').
       Why: Eliminates initial transients and ensures the sequence is on
       the chaotic attractor before we use it for cryptographic operations.
    2. Generate and store the next n iterations as float64 values.

    Args:
        x0: Initial condition in (0.1, 0.9).
        r: Chaotic parameter in (3.9, 4.0).
        n: Number of chaotic values to return.

    Returns:
        np.ndarray: 1D array of length n with dtype float64.
    """
    if n <= 0:
        raise ValueError("Length n must be a positive integer.")

    # Step 1: Burn-in phase (discard first 1000 iterations to eliminate transients)
    x = float(x0)
    for _ in range(1000):
        x = r * x * (1.0 - x)

    # Step 2: Generate the n values for permutation and diffusion
    seq = np.empty(n, dtype=np.float64)
    for i in range(n):
        x = r * x * (1.0 - x)
        seq[i] = x

    return seq
