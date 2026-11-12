"""Unit and integration tests for ChaosLock cryptographic engine.

Verifies:
1. Round-trip lossless recovery (0 differing pixels) on all 3 sample images.
2. Wrong password returns noise without crashing.
3. 1-character password change produces completely different encrypted output (avalanche effect).
4. Odd and arbitrary image dimensions (square, rectangular, prime dimensions).
5. Mode handling (RGB, grayscale 'L', and RGBA auto-conversion).
6. Deterministic key derivation and Logistic Map bounds.
"""
import pytest
import numpy as np
from PIL import Image

from engine.chaos import key_from_password, logistic_sequence
from engine.crypto import encrypt, decrypt
from engine.analysis import calculate_entropy, calculate_correlation, plot_histograms, run_full_analysis


class TestChaosEngine:
    """Test chaotic parameter derivation and sequence generation."""

    def test_key_derivation_deterministic(self):
        """Same password must always yield identical (x0, r)."""
        x0_a, r_a = key_from_password("MySecurePassword123")
        x0_b, r_b = key_from_password("MySecurePassword123")
        assert x0_a == x0_b
        assert r_a == r_b

    def test_key_derivation_bounds(self):
        """x0 must strictly be in (0.1, 0.9) and r in (3.9, 4.0)."""
        passwords = [
            "a", "12345678", "admin", "P@ssw0rd!#$%",
            "very_long_password_string_with_many_characters_and_symbols_1234567890"
        ]
        for pwd in passwords:
            x0, r = key_from_password(pwd)
            assert 0.1 < x0 < 0.9, f"x0 out of bounds for password {pwd}: {x0}"
            assert 3.9 < r < 4.0, f"r out of bounds for password {pwd}: {r}"

    def test_key_derivation_empty_password_raises(self):
        """Empty password should raise ValueError."""
        with pytest.raises(ValueError):
            key_from_password("")

    def test_logistic_sequence_length_and_type(self):
        """Sequence must match requested length, be float64, and stay in (0, 1)."""
        x0, r = key_from_password("test_pwd")
        seq = logistic_sequence(x0, r, 500)
        assert len(seq) == 500
        assert seq.dtype == np.float64
        assert np.all((seq > 0.0) & (seq < 1.0))

    def test_logistic_sequence_invalid_length(self):
        """Non-positive length must raise ValueError."""
        x0, r = key_from_password("test_pwd")
        with pytest.raises(ValueError):
            logistic_sequence(x0, r, 0)


class TestCryptoEngine:
    """Test image encryption, decryption, and edge cases."""

    @pytest.mark.parametrize(
        "sample_path",
        [
            "samples/shapes.png",
            "samples/photo.png",
            "samples/grayscale.png",
        ],
    )
    def test_round_trip_sample_images(self, sample_path):
        """Original image must be bit-for-bit identical to decrypted image (0 differing pixels)."""
        original = Image.open(sample_path)
        orig_arr = np.array(original)

        password = "UniversityInformationSecurity2026!"
        encrypted = encrypt(original, password)
        decrypted = decrypt(encrypted, password)
        dec_arr = np.array(decrypted)

        # Dimension and channel match
        assert orig_arr.shape == dec_arr.shape, "Shape mismatch after decryption"

        # 0 differing pixels
        differing_pixels = np.count_nonzero(orig_arr != dec_arr)
        assert differing_pixels == 0, f"Decryption failed with {differing_pixels} differing pixels on {sample_path}"

    def test_wrong_password_returns_noise_without_error(self):
        """Decryption with a wrong password must not raise an error and must return noise."""
        img = Image.open("samples/shapes.png")
        orig_arr = np.array(img.convert("RGB"))

        correct_pwd = "CorrectPassword123"
        wrong_pwd = "IncorrectPassword999"

        encrypted = encrypt(img, correct_pwd)
        # Must execute cleanly without exception
        wrong_decrypted = decrypt(encrypted, wrong_pwd)
        wrong_arr = np.array(wrong_decrypted)

        assert orig_arr.shape == wrong_arr.shape
        differing_bytes = np.count_nonzero(orig_arr != wrong_arr)
        # At least 95% of byte values should differ from original (showing high entropy noise)
        diff_ratio = differing_bytes / orig_arr.size
        assert diff_ratio > 0.95, f"Wrong password did not yield sufficient noise (diff ratio: {diff_ratio:.2%})"

    def test_one_character_password_avalanche_effect(self):
        """A single character change in password must yield entirely different ciphertexts."""
        img = Image.open("samples/shapes.png")

        pwd1 = "ChaosCipherKey_A"
        pwd2 = "ChaosCipherKey_B"  # 1-character difference

        enc1 = encrypt(img, pwd1)
        enc2 = encrypt(img, pwd2)

        arr1 = np.array(enc1)
        arr2 = np.array(enc2)

        # Ciphertexts should differ across virtually all pixels
        diff_count = np.count_nonzero(arr1 != arr2)
        diff_ratio = diff_count / arr1.size
        assert diff_ratio > 0.95, f"Avalanche effect insufficient: {diff_ratio:.2%} differing bytes"

        # Attempting to decrypt enc1 using pwd2 should fail to recover original
        orig_arr = np.array(img.convert("RGB"))
        cross_decrypted = decrypt(enc1, pwd2)
        cross_arr = np.array(cross_decrypted)
        cross_diff = np.count_nonzero(orig_arr != cross_arr)
        assert (cross_diff / orig_arr.size) > 0.95

    @pytest.mark.parametrize(
        "width,height,channels",
        [
            (100, 100, 3),  # Square RGB
            (120, 80, 3),   # Landscape rectangular RGB
            (75, 150, 3),   # Portrait rectangular RGB
            (67, 43, 3),    # Prime / odd dimensions RGB
            (93, 57, 1),    # Odd dimensions Grayscale
        ],
    )
    def test_arbitrary_and_odd_image_dimensions(self, width, height, channels):
        """Cipher must handle arbitrary, non-square, and odd prime dimensions."""
        if channels == 3:
            random_data = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
            img = Image.fromarray(random_data, mode="RGB")
        else:
            random_data = np.random.randint(0, 256, (height, width), dtype=np.uint8)
            img = Image.fromarray(random_data, mode="L")

        pwd = "DimensionTestPassword!"
        encrypted = encrypt(img, pwd)
        decrypted = decrypt(encrypted, pwd)

        dec_arr = np.array(decrypted)
        assert np.array_equal(random_data, dec_arr)

    def test_rgba_image_handling(self):
        """RGBA images must be cleanly converted to RGB and round-trip successfully as RGB."""
        # Create an RGBA image with varying alpha
        rgba_data = np.zeros((80, 80, 4), dtype=np.uint8)
        rgba_data[:, :, 0] = 200  # Red
        rgba_data[:, :, 1] = 100  # Green
        rgba_data[:, :, 2] = 50   # Blue
        rgba_data[:, :, 3] = 180  # Alpha
        img_rgba = Image.fromarray(rgba_data, mode="RGBA")

        pwd = "RGBATestPassword"
        encrypted = encrypt(img_rgba, pwd)
        decrypted = decrypt(encrypted, pwd)

        # Expected output is RGB version
        expected_rgb = np.array(img_rgba.convert("RGB"))
        dec_arr = np.array(decrypted)

        assert dec_arr.shape == expected_rgb.shape
        assert np.array_equal(expected_rgb, dec_arr)


class TestAnalysisModule:
    """Test histogram, adjacent pixel correlation, and Shannon entropy analysis."""

    def test_entropy_monochrome_image(self):
        """A uniform solid image has zero entropy (all pixels have probability 1.0)."""
        solid_arr = np.full((100, 100, 3), 128, dtype=np.uint8)
        entropy = calculate_entropy(solid_arr)
        assert entropy["overall"] == 0.0

    def test_entropy_encrypted_near_eight(self):
        """Encrypted image must have entropy close to 8.0 bits/pixel (> 7.95)."""
        img = Image.open("samples/shapes.png")
        encrypted = encrypt(img, "AnalysisTestPass123")

        orig_entropy = calculate_entropy(img)
        enc_entropy = calculate_entropy(encrypted)

        # Natural shapes image has lower entropy
        assert orig_entropy["overall"] < 7.5
        # Encrypted image has near-maximum 8.0 bits/pixel entropy
        assert enc_entropy["overall"] >= 7.95, f"Entropy too low: {enc_entropy['overall']}"

    def test_correlation_original_high_encrypted_near_zero(self):
        """Original image correlation should be high; encrypted should be near zero."""
        img = Image.open("samples/shapes.png")
        encrypted = encrypt(img, "CorrelationKey987!")

        orig_corr = calculate_correlation(img)
        enc_corr = calculate_correlation(encrypted)

        # Original image has high spatial correlation
        assert orig_corr["overall"] >= 0.80, f"Expected high original correlation: {orig_corr['overall']}"
        # Encrypted image correlation should be destroyed (|r| < 0.05)
        assert abs(enc_corr["overall"]) <= 0.05, f"Encrypted correlation not near zero: {enc_corr['overall']}"

    def test_plot_histograms_generates_valid_png(self):
        """Histogram plotting should generate valid PNG image bytes."""
        img = Image.open("samples/shapes.png")
        encrypted = encrypt(img, "PlotTestKey!")

        png_bytes = plot_histograms(img, encrypted)
        assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n"), "Did not produce a valid PNG header"
        assert len(png_bytes) > 1000

    def test_run_full_analysis_verdict(self):
        """Full analysis pipeline returns structured metrics and a PASS verdict for encrypted image."""
        img = Image.open("samples/shapes.png")
        encrypted = encrypt(img, "FullAnalysisKey!")

        result = run_full_analysis(img, encrypted)

        # Check required schema
        assert "original" in result
        assert "encrypted" in result
        assert "verdict" in result
        assert "histogram_bytes" in result

        verdict = result["verdict"]
        assert verdict["entropy_pass"] is True
        assert verdict["correlation_pass"] is True
        assert verdict["passed"] is True


