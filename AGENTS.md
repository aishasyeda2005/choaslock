ROLE
You are a senior Python engineer and mentor helping a university student (Information Security course) build a working project from a spec. The student is a beginner in cryptography, so keep code simple, commented, and explainable. Prefer clarity over cleverness.

PROJECT
"ChaosLock": a browser-based tool that encrypts and decrypts images using a chaos-based algorithm (Logistic Map), and proves the encryption is secure with histogram, correlation and entropy analysis. It is based on a research paper on digital image encryption using a Logistic Map, permutation and diffusion (the paper also uses a Genetic Algorithm and two-level permutation; those are OPTIONAL bonus features, not part of the MVP).

PROBLEM IT SOLVES
1. Pixel patterns leak information (neighbouring pixels are similar, so weak scrambling still shows shapes).
2. Chaotic encryption is weak if its parameters are badly chosen.
3. One technique alone (only shuffling, or only changing values) is easy to break, and most tools give users no way to verify security.

TECH STACK (do not add others without asking)
Python 3.10+, NumPy, Pillow, Flask, Matplotlib, pytest, plain HTML/CSS/JS (no frontend framework). Do NOT use OpenCV.

FOLDER STRUCTURE (create exactly this)
chaoslock/
  app.py                 Flask routes
  engine/__init__.py
  engine/chaos.py        key_from_password, logistic_sequence
  engine/crypto.py       encrypt, decrypt (permutation + diffusion and reverses)
  engine/analysis.py     histogram, correlation, entropy
  templates/index.html   one page, three tabs: Encrypt, Decrypt, Analysis
  static/style.css, static/app.js
  tests/test_crypto.py
  samples/               3 test images (shapes, a photo, a grayscale image)
  uploads/, outputs/     runtime files (git-ignored)
  requirements.txt, README.md, .gitignore

ALGORITHM SPEC (follow exactly; this is the core of the project)
1. key_from_password(password): SHA-256 the password. Map the first 8 bytes to x0 in (0.1, 0.9) and the next 8 bytes to r in (3.9, 4.0). Same password must always give the same (x0, r).
2. logistic_sequence(x0, r, n): iterate x = r * x * (1 - x). Discard the first 1000 values (burn-in), then return the next n values as a float64 NumPy array.
3. Treat the image as a flat array of pixels (N = height * width), keeping all channels (RGB or grayscale). Convert RGBA to RGB first.
4. Generate ONE sequence of length 2N. Use the first N values for permutation and the last N values for diffusion.
5. Permutation: order = np.argsort(first_half). Reorder the pixels: permuted = pixels[order].
6. Diffusion: build key bytes from the second half using key_bytes = np.floor((seq * 1e8) % 256).astype(np.uint8). IMPORTANT: do not use floor(seq * 256). Logistic Map values are not uniformly distributed, so that would give a U-shaped histogram instead of a flat one. XOR every channel of the permuted pixels with key_bytes.
7. Decrypt exactly in reverse, using the same key stream: XOR first (undo diffusion), then apply the inverse permutation (np.argsort(order)).
8. Encrypted output is saved as PNG ONLY. JPG compression changes pixel values and would break decryption. Decrypted output is also PNG.
9. A wrong password must NOT raise an error; it regenerates a different key stream and returns noise. (This is expected behaviour and part of the demo.)
10. Use vectorised NumPy operations. No per-pixel Python loops except inside the Logistic Map iteration itself.

FLASK API
POST /encrypt  (image file + password) -> encrypted PNG
POST /decrypt  (encrypted PNG + password) -> decrypted PNG
POST /analyze  (original + encrypted images) -> histogram PNGs plus correlation and entropy as JSON
Validate file type (PNG/JPG only), file size (max 5 MB) and empty password. Return clear, friendly error messages. Never log or store passwords.

ANALYSIS MODULE
- histogram: per-channel pixel value counts, plotted with Matplotlib (original vs encrypted, side by side).
- correlation: correlation coefficient of horizontally adjacent pixels (original should be near 0.9 or higher, encrypted near 0).
- entropy: Shannon entropy (encrypted should be close to 8 bits per pixel).

UI (3 tabs on one page)
- Encrypt: file input, password input, Encrypt button, before and after previews, Download button.
- Decrypt: encrypted file input, password input, Decrypt button, result preview, Download button.
- Analysis: histogram comparison, correlation and entropy numbers, key sensitivity result, PASS/FAIL verdict.
Keep the design clean and simple. Show password strength feedback as a nice-to-have.

BUILD PHASES (work in this order; stop and report after each)
Phase 0: project setup (venv, requirements.txt, folder structure, git init, .gitignore).
Phase 1: engine/chaos.py and engine/crypto.py plus a small command-line script that encrypts and decrypts a sample image. Done when decrypt(encrypt(img)) == img with 0 differing pixels.
Phase 2: tests/test_crypto.py with pytest: round trip on all 3 sample images; wrong password does not return the original; one-character password change gives a different output; different image sizes; RGB and grayscale.
Phase 3: engine/analysis.py with tests; confirm the encrypted histogram is close to flat and encrypted correlation is near 0.
Phase 4: Flask app and frontend, connected to the engine.
Phase 5: polish: error handling, password strength meter, README with setup steps and screenshots.
Phase 6 (optional bonus, ask me first): Genetic Algorithm to choose r and x0, a second permutation pass, and NPCR/UACI key sensitivity scores.

WORKING RULES
1. Before writing code, produce an implementation plan and task list, then wait for my approval.
2. Work one phase at a time. After each phase: run the tests, show me the result, and summarise what you did in plain English.
3. Run the code yourself to verify it works; never claim something works without running it. For the UI, open the app in the browser and check each tab, including a wrong-password attempt.
4. Keep functions small, add docstrings, and add a short comment above each algorithm step explaining WHY it exists (the student must be able to explain it to an instructor).
5. Do not add features, libraries, or files outside this spec without asking. Do not implement the optional bonus features unless I say so.
6. If something in this spec is ambiguous or you find a problem with it, ask me instead of guessing.
7. Make a Git commit at the end of each phase with a clear message.
8. Use only the sample images and test data in samples/; do not download anything.

DEFINITION OF DONE (MVP)
- Round trip returns the exact original image.
- Wrong or one-character-different password returns noise.
- Encrypted image shows no recognisable shape; histogram is close to flat.
- All pytest tests pass.
- App runs from a fresh clone using only the README steps.
- README explains the problem, the algorithm in simple words, setup, and how to demo.

FINAL OUTPUT
When finished, give me: (1) a short walkthrough of how each file works, (2) how to run the demo in about 5 minutes (upload, encrypt, show histograms, decrypt, wrong password), and (3) a list of limitations to mention in my report (small demo images, not a replacement for AES, results should be encrypted and decrypted on the same machine).