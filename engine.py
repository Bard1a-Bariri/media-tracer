import os
import time
import imagehash
import numpy as np
from PIL import Image
from PIL.ExifTags import TAGS
from transformers import pipeline

# Load classifiers...
try:
    classifier_1 = pipeline(
        "image-classification", model="umm-maybe/AI-image-detector"
    )
    classifier_2 = pipeline(
        "image-classification", model="dima806/deepfake_vs_real_image_detection"
    )
except Exception:
    classifier_1 = None
    classifier_2 = None


def generate_hashes(image_path):
    """Generates perceptual, difference, and average hashes."""
    try:
        img = Image.open(image_path)
        return {
            "phash": str(imagehash.phash(img)),
            "dhash": str(imagehash.dhash(img)),
            "ahash": str(imagehash.average_hash(img)),
        }
    except Exception as e:
        return {"error": f"Failed to generate hashes: {str(e)}"}


def parse_metadata(image_path):
    """Extracts Camera EXIF, PNG Text Chunks, File System properties, and Display Attributes."""
    parsed_meta = {}
    has_camera_exif = False
    has_png_chunks = False
    ai_flag = False

    try:
        img = Image.open(image_path)

        # 1. Structural & Display Metadata
        width, height = img.size
        parsed_meta["Display_Width_px"] = width
        parsed_meta["Display_Height_px"] = height
        parsed_meta["Aspect_Ratio"] = (
            round(width / height, 2) if height > 0 else 0
        )
        parsed_meta["Color_Mode"] = img.mode
        parsed_meta["File_Format"] = img.format

        # 2. File-System Timestamps
        file_stat = os.stat(image_path)
        parsed_meta["OS_Created_Time"] = time.ctime(file_stat.st_ctime)
        parsed_meta["OS_Modified_Time"] = time.ctime(file_stat.st_mtime)

        # 3. Camera EXIF
        try:
            exif_data = img._getexif()
            if exif_data:
                has_camera_exif = True
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    parsed_meta[f"EXIF_{tag_name}"] = str(value)
        except Exception:
            pass

        # 4. PNG Text Chunks
        if img.info:
            for key, val in img.info.items():
                if isinstance(val, (str, bytes)):
                    has_png_chunks = True
                    parsed_meta[f"PNG_Header_{key}"] = str(val)

        # 5. Raw Byte Scan
        ai_keywords = [
            "c2pa",
            "dall-e",
            "midjourney",
            "stable diffusion",
            "adobe firefly",
        ]
        with open(image_path, "rb") as f:
            raw_bytes = f.read().lower()
            if any(kw.encode() in raw_bytes for kw in ai_keywords):
                ai_flag = True

        return {
            "exif": parsed_meta,
            "has_exif": has_camera_exif,
            "has_png_chunks": has_png_chunks,
            "has_metadata": len(parsed_meta) > 0,
            "ai_signature_flagged": ai_flag,
        }

    except Exception as e:
        return {
            "exif": {"error": f"Failed to parse structure: {str(e)}"},
            "has_exif": False,
            "has_png_chunks": False,
            "has_metadata": False,
            "ai_signature_flagged": False,
        }


def _extract_model_score(classifier, image_path):
    if not classifier:
        return 0.05
    try:
        predictions = classifier(image_path)
        for pred in predictions:
            if pred["label"].lower() in [
                "artificial",
                "ai",
                "fake",
                "synthetic",
            ]:
                return float(pred["score"])
        return 0.05
    except Exception:
        return 0.05


def run_full_analysis(image_path):
    """Executes full forensic pipeline without extra helper functions."""
    hashes = generate_hashes(image_path)
    metadata = parse_metadata(image_path)

    # --- SCREENSHOT CHECK (Inline) ---
    is_screenshot = False
    if not metadata.get("has_exif", False):
        try:
            img = Image.open(image_path).convert("RGB")
            std_dev = np.std(np.array(img))
            # Standard deviation threshold set to 75.0 for app/UI graphics
            if std_dev < 75.0:
                is_screenshot = True
        except Exception:
            pass

    # --- AI DETECTION ---
    score1 = _extract_model_score(classifier_1, image_path)
    score2 = _extract_model_score(classifier_2, image_path)
    ai_probability = (score1 + score2) / 2.0

    if is_screenshot:
        ai_probability *= 0.35
    ai_probability = round(ai_probability, 2)

    # --- RISK SCORE (Inline) ---
    risk_score = 10
    if not metadata.get("has_exif", False) and not is_screenshot:
        risk_score += 20
    if metadata.get("ai_signature_flagged", False):
        risk_score += 40
    if ai_probability > 0.75:
        risk_score += 35
    elif ai_probability > 0.45:
        risk_score += 15

    risk_score = min(risk_score, 100)

    return {
        "file_name": os.path.basename(image_path),
        "risk_score": risk_score,
        "ai_probability": ai_probability,
        "is_screenshot": is_screenshot,
        "hashes": hashes,
        "metadata": metadata,
    }