import os
from geopy.geocoders import Nominatim
import imagehash
from PIL import Image
from PIL.ExifTags import TAGS
from transformers import pipeline

try:
    ai_classifier = pipeline(
        "image-classification", model="umm-maybe/AI-image-detector"
    )
except Exception:
    ai_classifier = None


def generate_hashes(image_path):
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


def detect_ai_pixels(image_path):
    if not ai_classifier:
        return 0.05

    try:
        predictions = ai_classifier(image_path)
        for pred in predictions:
            if pred["label"].lower() in [
                "artificial",
                "ai",
                "fake",
                "synthetic",
            ]:
                return round(float(pred["score"]), 2)

        return 0.05
    except Exception:
        return 0.05


def calculate_risk_score(hashes, metadata, ai_prob):
    score = 10

    if not metadata.get("has_exif", False):
        score += 25

    if metadata.get("ai_signature_flagged", False):
        score += 35

    if ai_prob > 0.70:
        score += 30
    elif ai_prob > 0.40:
        score += 15

    return min(score, 100)


def get_location_name(lat, lon):
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
    hashes = generate_hashes(image_path)

    metadata = parse_metadata(image_path)

    ai_probability = detect_ai_pixels(image_path)

    risk_score = calculate_risk_score(hashes, metadata, ai_probability)

    return {
        "file_name": os.path.basename(image_path),
        "risk_score": risk_score,
        "ai_probability": ai_probability,
        "hashes": hashes,
        "metadata": metadata,
    }