import os
import imagehash
import numpy as np
from PIL import Image
from PIL.ExifTags import TAGS
from geopy.geocoders import Nominatim
from transformers import pipeline

# 1. ENSEMBLE MODELS: Load two complementary classification models
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
    """Generates perceptual, difference, and average hashes for the image."""
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
    """Extracts EXIF metadata and scans raw binary bytes for AI keywords."""
    try:
        img = Image.open(image_path)
        exif_data = img._getexif() or {}

        parsed_exif = {}
        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, tag_id)
            parsed_exif[tag_name] = str(value)

        ai_flag = False
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
            "exif": parsed_exif,
            "has_exif": len(parsed_exif) > 0,
            "ai_signature_flagged": ai_flag,
        }
    except Exception as e:
        return {
            "exif": {},
            "has_exif": False,
            "ai_signature_flagged": False,
            "error": str(e),
        }


def is_digital_screenshot(image_path, metadata):
    """SCREENSHOT PRE-FILTER: Detects if an image is likely a UI screenshot / digital graphic

    rather than a photograph or AI art based on low color noise variance.
    """
    if metadata.get("has_exif", False):
        return False

    try:
        img = Image.open(image_path).convert("RGB")
        img_array = np.array(img)

        # Calculate standard deviation across color channels
        # Flat digital vectors and UI graphics have significantly lower color noise variance
        std_dev = np.std(img_array)

        if std_dev < 45.0:
            return True
    except Exception:
        pass

    return False


def _extract_model_score(classifier, image_path):
    """Helper function to extract AI probability score from a Hugging Face pipeline."""
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


def detect_ai_pixels(image_path, is_screenshot=False):
    """ENSEMBLE AI DETECTION: Averages scores from both models and applies screenshot weighting."""
    score1 = _extract_model_score(classifier_1, image_path)
    score2 = _extract_model_score(classifier_2, image_path)

    # Calculate ensemble average
    avg_score = (score1 + score2) / 2.0

    # Dampen score if image is a UI screen capture to avoid false positives
    if is_screenshot:
        avg_score = avg_score * 0.35

    return round(avg_score, 2)


def calculate_risk_score(hashes, metadata, ai_prob, is_screenshot):
    """RE-CALIBRATED RISK INDEX: Combines all factors with calibrated thresholds."""
    score = 10

    # Missing EXIF adds risk UNLESS it was recognized as a UI screenshot
    if not metadata.get("has_exif", False) and not is_screenshot:
        score += 20

    # Known AI byte signatures add high risk
    if metadata.get("ai_signature_flagged", False):
        score += 40

    # Re-calibrated AI probability risk additions
    if ai_prob > 0.75:
        score += 35
    elif ai_prob > 0.45:
        score += 15

    return min(score, 100)


def get_location_name(lat, lon):
    """Converts Latitude and Longitude into City, Country format."""
    try:
        geolocator = Nominatim(user_agent="media_tracer_forensics")
        location = geolocator.reverse((lat, lon), language="en")

        if location and "address" in location.raw:
            address = location.raw["address"]
            city = (
                address.get("city")
                or address.get("town")
                or address.get("village")
                or address.get("municipality")
                or "Unknown City"
            )

            country = address.get("country", "Unknown Country")
            return f"{city}, {country}"

    except Exception:
        pass

    return "Location Resolution Failed"


def run_full_analysis(image_path):
    """Main pipeline execution function."""
    # 1. Hashes & Metadata
    hashes = generate_hashes(image_path)
    metadata = parse_metadata(image_path)

    # 2. Check if file is a UI Screenshot / Flat Graphic
    is_screenshot = is_digital_screenshot(image_path, metadata)

    # 3. Detect AI pixels (with ensemble + screenshot adjustment)
    ai_probability = detect_ai_pixels(image_path, is_screenshot=is_screenshot)

    # 4. Calculate Risk Score
    risk_score = calculate_risk_score(
        hashes, metadata, ai_probability, is_screenshot
    )

    # 5. Return structured analysis output
    return {
        "file_name": os.path.basename(image_path),
        "risk_score": risk_score,
        "ai_probability": ai_probability,
        "is_screenshot": is_screenshot,
        "hashes": hashes,
        "metadata": metadata,
    }