"""Quality metrics module for evaluating AI watermark degradation and text/image quality.

Includes:
- Bigram Jaccard distance for text lexical divergence
- Cosine semantic similarity using Sentence Transformers (optional)
- PSNR (Peak Signal-to-Noise Ratio) for images
- SSIM (Structural Similarity Index) for images (with NumPy fallback if skimage is missing)
- LPIPS (Learned Perceptual Image Patch Similarity) (optional)
"""

from __future__ import annotations

import io
import math
import re
from typing import Any

import numpy as np
from PIL import Image


# =====================================================================
# Text Metrics
# =====================================================================

def _tokens(text: str) -> list[str]:
    """Helper to extract alpha-numeric lowercase tokens."""
    return re.findall(r"[a-za-z0-9]+", text.lower())


def _bigrams(tokens: list[str]) -> set[tuple[str, str]]:
    """Helper to extract bigrams from tokens list."""
    return set(zip(tokens, tokens[1:]))


def compute_lexical_divergence(original: str, candidate: str) -> float:
    """Compute bigram Jaccard distance between original and candidate texts.

    Value ranges from 0.0 (identical bigrams) to 1.0 (fully disjoint bigrams).
    """
    a = _tokens(original)
    b = _tokens(candidate)
    if not a and not b:
        return 0.0
    if not a or not b:
        return 1.0
    ba = _bigrams(a)
    bb = _bigrams(b)
    union = ba | bb
    if not union:
        return 0.0
    return 1.0 - len(ba & bb) / len(union)


def compute_semantic_similarity(original: str, candidate: str) -> float | None:
    """Compute cosine semantic similarity using a lightweight sentence-transformer model.

    Returns:
        float: Similarity value between -1.0 and 1.0 (usually 0.0 to 1.0 for embeddings).
        None: If sentence-transformers dependency is unavailable.
    """
    try:
        from sentence_transformers import SentenceTransformer, util
    except ImportError:
        return None

    try:
        # Load a lightweight model, setting local_files_only as a configuration safety check if needed
        model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        emb1 = model.encode(original, convert_to_tensor=True)
        emb2 = model.encode(candidate, convert_to_tensor=True)
        return float(util.cos_sim(emb1, emb2).item())
    except Exception:
        return None


# =====================================================================
# Image Metrics
# =====================================================================

def compute_psnr(img1_bytes: bytes, img2_bytes: bytes) -> float:
    """Compute Peak Signal-to-Noise Ratio (PSNR) in decibels (dB) between two images.

    Value ranges from 0 (very poor match) to infinity (identical images).
    """
    im1 = Image.open(io.BytesIO(img1_bytes)).convert("RGB")
    im2 = Image.open(io.BytesIO(img2_bytes)).convert("RGB")
    
    # Enforce size matching
    if im1.size != im2.size:
        im2 = im2.resize(im1.size, Image.Resampling.BILINEAR)

    arr1 = np.array(im1, dtype=np.float64)
    arr2 = np.array(im2, dtype=np.float64)

    mse = np.mean((arr1 - arr2) ** 2)
    if mse == 0:
        return float("inf")

    return 20 * math.log10(255.0 / math.sqrt(mse))


def compute_ssim(img1_bytes: bytes, img2_bytes: bytes) -> float:
    """Compute Structural Similarity Index (SSIM) between two images.

    Value ranges from -1.0 to 1.0 (with 1.0 meaning perfect structural match).
    Uses scikit-image if available, falling back to a global NumPy math implementation.
    """
    im1 = Image.open(io.BytesIO(img1_bytes)).convert("RGB")
    im2 = Image.open(io.BytesIO(img2_bytes)).convert("RGB")

    # Enforce size matching
    if im1.size != im2.size:
        im2 = im2.resize(im1.size, Image.Resampling.BILINEAR)

    arr1 = np.array(im1, dtype=np.float64)
    arr2 = np.array(im2, dtype=np.float64)

    # 1. Try to use skimage if available
    try:
        from skimage.metrics import structural_similarity as ssim_fn
        # For RGB images, channel_axis or multichannel keyword depends on skimage version
        import inspect
        sig = inspect.signature(ssim_fn)
        if "channel_axis" in sig.parameters:
            return float(ssim_fn(arr1, arr2, channel_axis=2, data_range=255.0))
        elif "multichannel" in sig.parameters:
            return float(ssim_fn(arr1, arr2, multichannel=True, data_range=255.0))
        else:
            return float(ssim_fn(arr1, arr2, data_range=255.0))
    except ImportError:
        pass

    # 2. Pure NumPy Fallback (Global SSIM computation)
    # Formula: ssim = (2*mu1*mu2 + c1)*(2*cov + c2) / ((mu1^2 + mu2^2 + c1)*(var1 + var2 + c2))
    mu1 = np.mean(arr1)
    mu2 = np.mean(arr2)
    var1 = np.var(arr1)
    var2 = np.var(arr2)
    cov = np.mean((arr1 - mu1) * (arr2 - mu2))

    c1 = (0.01 * 255) ** 2
    c2 = (0.03 * 255) ** 2

    ssim = (2 * mu1 * mu2 + c1) * (2 * cov + c2) / ((mu1**2 + mu2**2 + c1) * (var1 + var2 + c2))
    return float(ssim)


def compute_lpips(img1_bytes: bytes, img2_bytes: bytes) -> float | None:
    """Compute Learned Perceptual Image Patch Similarity (LPIPS) using PyTorch model.

    Returns:
        float: Distance metric from 0.0 (identical perception) upwards.
        None: If LPIPS / PyTorch is not available.
    """
    try:
        import torch
        import lpips
    except ImportError:
        return None

    try:
        im1 = Image.open(io.BytesIO(img1_bytes)).convert("RGB")
        im2 = Image.open(io.BytesIO(img2_bytes)).convert("RGB")

        # Enforce size matching
        if im1.size != im2.size:
            im2 = im2.resize(im1.size, Image.Resampling.BILINEAR)

        # Convert to torch tensor formatted for LPIPS: [1, 3, H, W] normalized to [-1, 1]
        def to_tensor(img: Image.Image) -> torch.Tensor:
            t = torch.from_numpy(np.array(img)).permute(2, 0, 1).float()
            return (t / 127.5) - 1.0

        t1 = to_tensor(im1).unsqueeze(0)
        t2 = to_tensor(im2).unsqueeze(0)

        # Load LPIPS vgg net (usually cached locally, fail if offline and not cached)
        loss_fn = lpips.LPIPS(net="vgg", verbose=False)
        with torch.no_grad():
            dist = loss_fn(t1, t2)
        return float(dist.item())
    except Exception:
        return None
