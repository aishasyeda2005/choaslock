"""Image encryption and decryption engine for ChaosLock.

Implements a symmetric chaotic image cipher combining:
1. Spatial Permutation: Scrambles pixel locations via chaotic rank sorting.
2. Value Diffusion: Modifies pixel values via chaotic XOR masking.

Both operations are reversible given the exact same password and key sequence.
"""
from typing import Union
import os
from PIL import Image
import numpy as np

try:
    from engine.chaos import key_from_password, logistic_sequence
except ImportError:
    from chaos import key_from_password, logistic_sequence


def _prepare_image(image_input: Union[str, os.PathLike, Image.Image]) -> tuple[np.ndarray, str, tuple[int, int]]:
    """Load an image and convert it to a standardized NumPy array.

    Handles format normalization:
    - RGBA images are converted to RGB (stripping alpha channel as PNG transparency
      should not distort cryptographic diffusion).
    - Grayscale ('L') images are preserved as single-channel.
    - Other modes (e.g. palette 'P', 'CMYK') are converted to RGB.

    Args:
        image_input: File path, Path object, or PIL Image instance.

    Returns:
        tuple (arr, mode, (height, width)):
            arr (np.ndarray): Pixel array of uint8.
            mode (str): 'RGB' or 'L'.
            (height, width): Dimensions of the image.
    """
    if isinstance(image_input, Image.Image):
        img = image_input
    else:
        img = Image.open(image_input)

    # Standardize image color modes
    if img.mode == "RGBA":
        # Convert RGBA to RGB (strip transparency for consistent channel encryption)
        img = img.convert("RGB")
    elif img.mode != "L" and img.mode != "RGB":
        # Standardize other modes (e.g. palette 'P' or 'CMYK') to RGB
        img = img.convert("RGB")

    mode = img.mode
    width, height = img.size
    arr = np.array(img, dtype=np.uint8)

    return arr, mode, (height, width)


def encrypt(
    image_input: Union[str, os.PathLike, Image.Image],
    password: str,
    output_path: Union[str, os.PathLike, None] = None,
) -> Image.Image:
    """Encrypt an image using Logistic Map chaotic permutation and diffusion.

    Algorithm steps:
    1. Load image, convert RGBA to RGB, and obtain dimensions (H, W).
       Total pixels N = H * W.
    2. Derive (x0, r) from password using SHA-256 (key_from_password).
    3. Generate a single chaotic sequence of length 2N (logistic_sequence).
       - First N values: used for pixel permutation.
       - Last N values: used for pixel diffusion.
    4. Permutation:
       - Sort the first half with np.argsort to get an index permutation order.
       - Reorder flattened pixels: permuted = pixels[order].
       - Why: Neighboring pixels in natural images have high correlation. Shuffling
         pixel positions destroys spatial correlation across the entire image.
    5. Diffusion:
       - Derive 8-bit key bytes: key_bytes = floor((diff_seq * 1e8) % 256).
       - Why: Direct Logistic Map values follow a U-shaped distribution. Scaling by
         10^8 and taking modulo 256 yields a flat, uniform distribution of bytes [0, 255].
       - XOR every channel of the permuted pixels with key_bytes.
       - Why: XOR alters pixel values, completely flattening the histogram and preventing
         frequency/statistical attacks.
    6. Reshape back to (H, W, Channels) and format as PNG.
       Why PNG: Lossless compression is mandatory; lossy JPEG compression modifies
       byte values, which permanently breaks exact decryption.

    Args:
        image_input: Input image path or PIL Image.
        password: User-provided encryption password.
        output_path: Optional file path to save the encrypted PNG.

    Returns:
        Image.Image: The encrypted image in PNG-compatible format.
    """
    arr, mode, (height, width) = _prepare_image(image_input)
    num_pixels = height * width

    # Reshape pixels into a 2D matrix: (N, channels)
    # This vectorizes operations across all color channels simultaneously
    is_grayscale = (mode == "L")
    if is_grayscale:
        flat_pixels = arr.reshape(num_pixels, 1)
    else:
        flat_pixels = arr.reshape(num_pixels, 3)

    # Step 1: Derive chaotic parameters (x0, r) from password
    x0, r = key_from_password(password)

    # Step 2: Generate ONE chaotic sequence of length 2N
    seq = logistic_sequence(x0, r, 2 * num_pixels)
    first_half = seq[:num_pixels]   # For permutation
    second_half = seq[num_pixels:]  # For diffusion

    # Step 3: Permutation (shuffle pixel spatial positions)
    # np.argsort returns the indices that would sort the chaotic sequence
    order = np.argsort(first_half)
    permuted = flat_pixels[order]

    # Step 4: Diffusion (alter pixel numerical values)
    # Modulo 256 with 1e8 multiplier flattens the U-shaped Logistic distribution
    key_bytes = np.floor((second_half * 1e8) % 256).astype(np.uint8)
    # Broadcast key_bytes across all channels (shape: (N, 1) ^ (N, Channels))
    diffused = permuted ^ key_bytes[:, None]

    # Step 5: Reshape back into 2D/3D image array
    if is_grayscale:
        encrypted_arr = diffused.reshape(height, width)
    else:
        encrypted_arr = diffused.reshape(height, width, 3)

    encrypted_img = Image.fromarray(encrypted_arr, mode=mode)

    if output_path:
        # Guarantee saving as PNG only (lossless format)
        encrypted_img.save(output_path, format="PNG")

    return encrypted_img


def decrypt(
    image_input: Union[str, os.PathLike, Image.Image],
    password: str,
    output_path: Union[str, os.PathLike, None] = None,
) -> Image.Image:
    """Decrypt an encrypted image by reversing diffusion and permutation.

    Algorithm steps (exact inverse of encryption):
    1. Load encrypted PNG and flatten to (N, channels).
    2. Re-derive (x0, r) from password and generate the exact same 2N sequence.
    3. Undo Diffusion FIRST:
       - Since XOR is an involution (A ^ B ^ B = A), XORing the encrypted pixels
         with key_bytes restores the permuted state.
    4. Undo Permutation SECOND:
       - Compute the inverse permutation via np.argsort(order).
       - Applying inverse_order restores pixels back to their original coordinates.
    5. Reshape back to original dimensions (H, W, Channels).

    Note on wrong password:
    If a wrong password is supplied, SHA-256 produces a different key stream.
    Decryption still runs without error, but yields pure pseudorandom noise.

    Args:
        image_input: Encrypted PNG image path or PIL Image.
        password: Plaintext password used for decryption.
        output_path: Optional file path to save the decrypted PNG.

    Returns:
        Image.Image: The decrypted image.
    """
    arr, mode, (height, width) = _prepare_image(image_input)
    num_pixels = height * width

    is_grayscale = (mode == "L")
    if is_grayscale:
        flat_pixels = arr.reshape(num_pixels, 1)
    else:
        flat_pixels = arr.reshape(num_pixels, 3)

    # Step 1: Re-derive chaotic parameters (x0, r) from password
    x0, r = key_from_password(password)

    # Step 2: Regenerate the identical 2N sequence
    seq = logistic_sequence(x0, r, 2 * num_pixels)
    first_half = seq[:num_pixels]   # For permutation
    second_half = seq[num_pixels:]  # For diffusion

    # Step 3: Undo Diffusion (XOR first)
    key_bytes = np.floor((second_half * 1e8) % 256).astype(np.uint8)
    un_diffused = flat_pixels ^ key_bytes[:, None]

    # Step 4: Undo Permutation (Inverse permutation second)
    # Mathematical property: np.argsort(order) maps sorted indices back to their original positions
    order = np.argsort(first_half)
    inverse_order = np.argsort(order)
    restored = un_diffused[inverse_order]

    # Step 5: Reshape to original image dimensions
    if is_grayscale:
        decrypted_arr = restored.reshape(height, width)
    else:
        decrypted_arr = restored.reshape(height, width, 3)

    decrypted_img = Image.fromarray(decrypted_arr, mode=mode)

    if output_path:
        decrypted_img.save(output_path, format="PNG")

    return decrypted_img


if __name__ == "__main__":
    import sys

    # Quick command-line test demonstration
    test_sample = "samples/shapes.png"
    if not os.path.exists(test_sample):
        print(f"Sample file not found: {test_sample}")
        sys.exit(1)

    print(f"[CLI] Running round-trip test on {test_sample}...")
    sample_img = Image.open(test_sample).convert("RGB")
    sample_arr = np.array(sample_img)

    enc = encrypt(sample_img, "SecretKey123")
    dec = decrypt(enc, "SecretKey123")
    dec_arr = np.array(dec)

    diff = np.count_nonzero(sample_arr != dec_arr)
    print(f"[CLI] Differing pixels: {diff}")
    if diff == 0:
        print("[CLI] SUCCESS: Decrypted image exactly matches the original!")
    else:
        print(f"[CLI] FAILURE: {diff} differing pixels found.")
        sys.exit(1)

