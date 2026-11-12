# ChaosLock: Chaotic Image Encryption & Security Analysis

> An educational, browser-based digital image encryption and analysis tool implementing a symmetric chaotic cipher (Logistic Map) with permutation, diffusion, and empirical security verification. Designed for university Information Security coursework.

---

## 1. Problem Statement

Standard text encryption algorithms cannot be applied directly to digital images without preprocessing due to two primary characteristics of visual data:

1. **High Data Redundancy and Spatial Correlation:** In natural images, neighbouring pixels share almost identical values ($\rho \ge 0.90$). If an algorithm only shuffles pixel positions (permutation alone) or only changes values without sufficient diffusion, visual outlines and shapes still leak through.
2. **Chaotic Parameter Sensitivity:** Chaotic systems like the Logistic Map are highly sensitive to initial conditions, but only behave chaotically within specific parameter ranges ($r \in [3.9, 4.0]$). Poor parameter choice collapses the system into periodic orbits or fixed points.
3. **Lack of Empirical Verification:** Most encryption demonstrations offer no scientific proof of security. ChaosLock includes an integrated statistical analysis suite (Histograms, Shannon Entropy, and Adjacent Pixel Correlation) to prove that the ciphertext achieves cryptographic randomness.

---

## 2. Cryptographic Algorithm Specification

ChaosLock implements a two-stage symmetric cipher: **Spatial Permutation** followed by **Value Diffusion**, driven by a single chaotic stream.

```
                  +--------------------------+
                  |  User Password (Plain)   |
                  +--------------------------+
                               |
                        SHA-256 Hashing
                               |
               +---------------+---------------+
               |                               |
       Bytes [0:8] -> x0               Bytes [8:16] -> r
     x0 in (0.1, 0.9)                  r in (3.9, 4.0)
               |                               |
               +---------------+---------------+
                               |
                    Logistic Map Iteration
                  x_{k+1} = r * x_k * (1 - x_k)
                    (1,000 Burn-In Iterations)
                               |
               Generate Sequence of Length 2N
             (where N = Height * Width of Image)
                               |
               +---------------+---------------+
               |                               |
       First N Values                   Second N Values
      (for Permutation)                 (for Diffusion)
               |                               |
          np.argsort                       Scale & Modulo
      Index Order Vector           key_bytes = floor(seq * 1e8) % 256
               |                               |
               v                               v
    Pixels[order] (Shuffled)   ------->   XOR Diffusion (Masked)
                                               |
                                               v
                                      Encrypted PNG Output
```

### Mathematical Steps Explained Simply:

1. **Deterministic Seeding (`key_from_password`):**
   - The password is hashed using **SHA-256**, ensuring the *avalanche effect* (changing a single character flips roughly 50% of the bits).
   - The first 8 bytes map to the initial state $x_0 \in (0.1, 0.9)$. Keeping $x_0$ away from $0$ and $1$ prevents numerical collapse at the map's fixed points.
   - The next 8 bytes map to the parameter $r \in (3.9, 4.0)$, where the Logistic Map exhibits a strictly positive Lyapunov exponent (full chaos).

2. **Chaotic Sequence Generation (`logistic_sequence`):**
   - Formula: $x_{k+1} = r \cdot x_k \cdot (1 - x_k)$.
   - The first **1,000 values are discarded** (burn-in period). This eliminates initial transients and guarantees that the sequence has settled onto the chaotic attractor.
   - A sequence of length $2N$ ($N = \text{height} \times \text{width}$) is generated in `float64` precision.

3. **Spatial Permutation:**
   - `order = np.argsort(first_half)`: Computes the permutation indices that sort the first $N$ chaotic values.
   - `permuted = pixels[order]`: Reorders pixel positions. This breaks adjacent pixel correlation and scatters neighboring pixels across the entire canvas.

4. **Value Diffusion:**
   - `key_bytes = np.floor((second_half * 1e8) % 256).astype(np.uint8)`
   - *Why not `floor(seq * 256)`?* The Logistic Map has an invariant probability density of $f(x) = \frac{1}{\pi\sqrt{x(1-x)}}$, which produces a U-shaped distribution with severe spikes near 0 and 1. Multiplying by $10^8$ and taking modulo 256 samples the fractional chaotic digits, yielding an evenly flat, uniform byte distribution between 0 and 255.
   - Every channel of each permuted pixel is XORed with `key_bytes`. XOR is an involution ($A \oplus B \oplus B = A$), perfectly altering pixel values while remaining completely reversible.

5. **Reversible Decryption:**
   - Decryption performs the exact inverse steps in reverse order:
     1. **Undo Diffusion First:** $\text{un\_diffused} = \text{encrypted} \oplus \text{key\_bytes}$.
     2. **Undo Permutation Second:** $\text{restored} = \text{un\_diffused}[\text{argsort}(\text{order})]$.
   - If an incorrect password is used, SHA-256 produces an uncorrelated key stream, resulting in pure high-entropy noise without throwing exceptions.

6. **Lossless Format Requirement:**
   - Encrypted and decrypted images are saved exclusively as **PNG**. Lossy compression formats (such as JPEG) modify pixel byte values, permanently destroying the exact XOR diffusion and making accurate decryption impossible.

---

## 3. Project Structure

```
chaoslock/
  app.py                 Flask web application and REST API routes
  engine/
    __init__.py          Package initializer
    chaos.py             Chaotic key derivation and Logistic Map generator
    crypto.py            Permutation, diffusion, encryption, and decryption routines
    analysis.py          Shannon entropy, adjacent pixel correlation, and histogram generator
  templates/
    index.html           Single-page web interface (Encrypt, Decrypt, Analysis tabs)
  static/
    style.css            Modern cybersecurity/academic theme
    app.js               Frontend client logic, previewing, and AJAX calls
  tests/
    test_crypto.py       Comprehensive pytest suite (27 unit and integration tests)
  samples/
    shapes.png           Test image 1: High-contrast geometric shapes (RGB)
    photo.png            Test image 2: Continuous tone landscape gradients (RGB)
    grayscale.png        Test image 3: Single-channel 8-bit texture (Grayscale)
  uploads/               Temporary upload workspace (git-ignored)
  outputs/               Output files and temporary exports (git-ignored)
  requirements.txt       Pinned Python dependencies
  README.md              Project documentation and presentation guide
  .gitignore             Git exclusion rules
```

---

## 4. Setup & Running (Fresh Environment)

### Prerequisites
- Python 3.10+ (tested on Python 3.10 through 3.14)
- Git

### Installation Steps

1. **Clone the repository and enter directory:**
   ```bash
   git clone <repo-url>
   cd "choas lock"
   ```

2. **Create and activate a virtual environment:**
   - **Windows (PowerShell):**
     ```powershell
     python -m venv venv
     .\venv\Scripts\Activate.ps1
     ```
   - **Linux / macOS:**
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the automated test suite:**
   ```bash
   pytest -v
   ```
   *Expected: All 27 tests pass (100% pass rate).*

5. **Start the web application:**
   ```bash
   python app.py
   ```

6. **Open in browser:**
   Navigate to [http://127.0.0.1:5000](http://127.0.0.1:5000).

---

## 5. Five-Minute Live Demonstration Guide

Follow these steps for an instructor or classroom presentation:

1. **Step 1: Encrypting an Image (Tab 1)**
   - Open [http://127.0.0.1:5000](http://127.0.0.1:5000).
   - In the **Encrypt** tab, select `samples/shapes.png`.
   - Enter a secure password (e.g., `ChaosKey2026!`). Note the real-time **Password Strength Meter** evaluating entropy.
   - Click **Encrypt Image**.
   - Point out the result: The image is transformed into pure visual static with no recognizable outlines.
   - Click **Send to Decrypt Tab** and **Send to Analysis Tab** to queue the encrypted result.

2. **Step 2: Proving Cryptographic Security (Tab 3)**
   - Switch to the **Security Analysis** tab.
   - Upload `samples/shapes.png` as Original and the newly encrypted PNG as Encrypted.
   - Click **Run Security Verification**.
   - Highlight the three proof metrics:
     - **Shannon Entropy:** Shows original image entropy (~1.44 bits/pixel for geometric shapes) rising to **> 7.99 bits/pixel** (theoretical ceiling is 8.00).
     - **Horizontal Correlation:** Shows original high correlation ($\rho \approx 0.96$) dropping to **$\rho \approx 0.00$**, proving that spatial dependency has been destroyed.
     - **Histograms:** Show the side-by-side plot. The original has sharp spikes; the encrypted histogram is completely flat across all 256 bins.
     - Note the **PASS** security verdict banner.

3. **Step 3: Flawless Decryption (Tab 2)**
   - Switch to the **Decrypt** tab.
   - With the correct password entered, click **Decrypt Image**.
   - Note the result: The geometric shapes are restored with **0 differing pixels**.

4. **Step 4: Wrong Password Resistance Demo (Tab 2)**
   - Click **Try Wrong Password Demo** (or alter one single character).
   - Click **Decrypt Image**.
   - Point out that the tool does not crash or display an error dialog; instead, it outputs pure uncorrelated static, demonstrating the *avalanche effect* and brute-force resistance.

---

## 6. Limitations & Academic Discussion Points

When defending this project in an Information Security course, mention the following academic considerations:

1. **Floating-Point Determinism Across Architectures:**
   - The Logistic Map uses 64-bit IEEE 754 floating-point arithmetic. Minor CPU microcode or compiler rounding discrepancies across different hardware architectures can lead to divergent chaotic trajectories after thousands of iterations. In a production system, integer fixed-point arithmetic is preferred for cross-platform portability.
2. **Computational Complexity on Massive Images:**
   - The permutation stage relies on sorting $N$ elements (`O(N log N)` via `np.argsort`). While near-instantaneous for images under $1024 \times 1024$ pixels, 4K or 8K images require significant memory and processing time.
3. **Cipher Purpose vs. Standard Block Ciphers:**
   - ChaosLock is designed specifically for bulk visual data (where spatial correlation and flat histograms are the primary concern). It is an academic demonstration of chaotic permutation-diffusion principles and is not a replacement for authenticated modern standards like AES-256-GCM, which include message authentication codes (MACs) and protection against chosen-plaintext attacks.
