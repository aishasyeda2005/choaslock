"""Image security analysis module for ChaosLock.

Evaluates encryption quality using three standard cryptographic metrics:
1. Shannon Entropy: Measures information randomness (ideal: ~8.0 bits/pixel).
2. Adjacent Pixel Correlation: Measures spatial pixel dependency (ideal: ~0.0).
3. Histogram Uniformity: Verifies flat distribution across all 256 pixel values.
"""
from typing import Union, Dict, Any, Optional
import io
import os
import numpy as np
from PIL import Image
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend suitable for server environments
import matplotlib.pyplot as plt


def calculate_entropy(image_input: Union[str, os.PathLike, Image.Image, np.ndarray]) -> dict[str, Any]:
    """Calculate the Shannon Entropy of an image.

    Formula:
        H(X) = - SUM( p(i) * log2(p(i)) ) for i in [0, 255]

    Why this metric matters:
    - For an 8-bit discrete symbol distribution, maximum entropy is log2(256) = 8.0 bits.
    - A natural image has low entropy (typically 6.0 to 7.5) because pixel values cluster
      around dominant colors and patterns.
    - An ideally encrypted image behaves like pure white noise, meaning all 256 byte
      values are equiprobable (p(i) = 1/256), yielding an entropy close to 8.0 bits/pixel.
      Values above 7.99 indicate virtually no information leakage.

    Args:
        image_input: Image path, PIL Image, or NumPy array.

    Returns:
        dict: Channel-specific and overall mean entropy values.
    """
    arr = _to_numpy_array(image_input)

    # Handle grayscale vs multi-channel images
    if arr.ndim == 2:
        channels = [arr]
        channel_names = ["Grayscale"]
    else:
        channels = [arr[:, :, c] for c in range(arr.shape[2])]
        channel_names = ["Red", "Green", "Blue"][: arr.shape[2]]

    results = {}
    values = []

    for name, channel in zip(channel_names, channels):
        # Step 1: Count frequency of each byte value 0..255
        counts = np.bincount(channel.ravel(), minlength=256)
        # Step 2: Compute empirical probability distribution p(i)
        probs = counts / counts.sum()
        # Step 3: Filter non-zero probabilities (0 * log2(0) = 0 by limit definition)
        non_zero_probs = probs[probs > 0]
        # Step 4: Compute Shannon entropy
        h = float(-np.sum(non_zero_probs * np.log2(non_zero_probs)))
        results[name] = round(h, 4)
        values.append(h)

    results["overall"] = round(float(np.mean(values)), 4)
    return results


def calculate_correlation(image_input: Union[str, os.PathLike, Image.Image, np.ndarray]) -> dict[str, Any]:
    """Calculate Pearson correlation coefficient between horizontally adjacent pixels.

    Formula:
        r_xy = cov(x, y) / (std(x) * std(y))
        where x is pixel[r, c] and y is pixel[r, c + 1]

    Why this metric matters:
    - Natural images have high spatial correlation (r >= 0.90) because neighboring
      pixels usually represent the same object or background.
    - Effective chaotic permutation and diffusion destroys spatial continuity,
      reducing correlation to near zero (|r| < 0.05).

    Args:
        image_input: Image path, PIL Image, or NumPy array.

    Returns:
        dict: Channel-specific and overall mean correlation coefficients.
    """
    arr = _to_numpy_array(image_input)

    if arr.ndim == 2:
        channels = [arr]
        channel_names = ["Grayscale"]
    else:
        channels = [arr[:, :, c] for c in range(arr.shape[2])]
        channel_names = ["Red", "Green", "Blue"][: arr.shape[2]]

    results = {}
    values = []

    for name, channel in zip(channel_names, channels):
        # Pair horizontally adjacent pixels across all rows
        # x: columns 0 to W-2, y: columns 1 to W-1
        x = channel[:, :-1].astype(np.float64).ravel()
        y = channel[:, 1:].astype(np.float64).ravel()

        std_x = np.std(x)
        std_y = np.std(y)

        # Handle edge case: flat/monochrome image with zero variance
        if std_x == 0 or std_y == 0:
            corr = 0.0
        else:
            mean_x = np.mean(x)
            mean_y = np.mean(y)
            covariance = np.mean((x - mean_x) * (y - mean_y))
            corr = float(covariance / (std_x * std_y))

        results[name] = round(corr, 4)
        values.append(corr)

    results["overall"] = round(float(np.mean(values)), 4)
    return results


def plot_histograms(
    orig_input: Union[str, os.PathLike, Image.Image, np.ndarray],
    enc_input: Union[str, os.PathLike, Image.Image, np.ndarray],
    output_path: Optional[Union[str, os.PathLike]] = None,
) -> bytes:
    """Generate a side-by-side histogram comparison figure (Original vs Encrypted).

    Why this visual matters:
    - An unencrypted image has distinctive peaks and valleys in its histogram,
      revealing contrast and color balance (vulnerable to frequency attacks).
    - An encrypted image must produce a completely flat, uniform distribution,
      proving that pixel values have been diffused uniformly into pseudo-random bytes.

    Args:
        orig_input: Original image.
        enc_input: Encrypted image.
        output_path: Optional path to save the generated PNG plot.

    Returns:
        bytes: PNG-encoded plot image bytes.
    """
    orig_arr = _to_numpy_array(orig_input)
    enc_arr = _to_numpy_array(enc_input)

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    fig.patch.set_facecolor("#f8f9fa")

    # Plot original histogram
    _render_histogram_axis(axes[0], orig_arr, title="Original Image Histogram")
    # Plot encrypted histogram
    _render_histogram_axis(axes[1], enc_arr, title="Encrypted Image Histogram (Diffused)")

    plt.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=120, bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    image_bytes = buf.getvalue()

    if output_path:
        with open(output_path, "wb") as f:
            f.write(image_bytes)

    return image_bytes


def run_full_analysis(
    orig_input: Union[str, os.PathLike, Image.Image, np.ndarray],
    enc_input: Union[str, os.PathLike, Image.Image, np.ndarray],
    histogram_output_path: Optional[Union[str, os.PathLike]] = None,
) -> dict[str, Any]:
    """Execute complete security verification comparing original and encrypted images.

    Returns:
        dict containing:
        - original metrics (entropy, correlation)
        - encrypted metrics (entropy, correlation)
        - verdict (PASS/FAIL checks against cryptographic thresholds)
    """
    orig_entropy = calculate_entropy(orig_input)
    enc_entropy = calculate_entropy(enc_input)

    orig_corr = calculate_correlation(orig_input)
    enc_corr = calculate_correlation(enc_input)

    # Cryptographic evaluation thresholds:
    # 1. Entropy: Ideal is 8.0; >= 7.95 is considered high quality randomness
    entropy_pass = enc_entropy["overall"] >= 7.95
    # 2. Correlation: Ideal is 0.0; |r| <= 0.05 confirms spatial decorrelation
    corr_pass = abs(enc_corr["overall"]) <= 0.05
    # 3. Overall pass requires meeting both criteria
    overall_pass = entropy_pass and corr_pass

    plot_bytes = plot_histograms(orig_input, enc_input, output_path=histogram_output_path)

    return {
        "original": {
            "entropy": orig_entropy,
            "correlation": orig_corr,
        },
        "encrypted": {
            "entropy": enc_entropy,
            "correlation": enc_corr,
        },
        "verdict": {
            "entropy_pass": entropy_pass,
            "correlation_pass": corr_pass,
            "passed": overall_pass,
            "summary": (
                "PASS: Cipher satisfies cryptographic diffusion and permutation criteria."
                if overall_pass
                else "FAIL: Residual correlation or non-uniform distribution detected."
            ),
        },
        "histogram_bytes": plot_bytes,
    }


def _render_histogram_axis(ax, arr: np.ndarray, title: str):
    """Helper to render channel histograms on a matplotlib Axes."""
    ax.set_facecolor("#ffffff")
    ax.set_title(title, fontsize=12, fontweight="bold", pad=10)
    ax.set_xlabel("Pixel Value (0 - 255)", fontsize=10)
    ax.set_ylabel("Pixel Frequency", fontsize=10)
    ax.set_xlim([0, 256])
    ax.grid(True, linestyle="--", alpha=0.4)

    bins = np.arange(257)

    if arr.ndim == 2:
        ax.hist(arr.ravel(), bins=bins, color="#495057", alpha=0.7, label="Grayscale")
    else:
        colors = ["#e63946", "#2a9d8f", "#1d3557"]
        labels = ["Red Channel", "Green Channel", "Blue Channel"]
        for c in range(min(3, arr.shape[2])):
            ax.hist(arr[:, :, c].ravel(), bins=bins, color=colors[c], alpha=0.5, label=labels[c])

    ax.legend(loc="upper right", framealpha=0.8)


def _to_numpy_array(image_input: Union[str, os.PathLike, Image.Image, np.ndarray]) -> np.ndarray:
    """Helper to ensure image input is converted to a clean NumPy array."""
    if isinstance(image_input, np.ndarray):
        return image_input
    if isinstance(image_input, Image.Image):
        img = image_input
    else:
        img = Image.open(image_input)

    if img.mode == "RGBA":
        img = img.convert("RGB")
    elif img.mode != "L" and img.mode != "RGB":
        img = img.convert("RGB")

    return np.array(img, dtype=np.uint8)

