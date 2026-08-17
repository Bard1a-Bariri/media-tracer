import os
import time
from PIL import Image
from PIL.ExifTags import GPSTAGS, IFD, TAGS
import imagehash

AI_KEYWORDS = [
    b"c2pa",
    b"dall-e",
    b"midjourney",
    b"stable diffusion",
    b"adobe firefly",
]


class ForensicEngine:

    def __init__(self):
        self.classifier_1 = None
        self.classifier_2 = None
        self._models_loaded = False

    def load_models(self):
        if self._models_loaded:
            return
        try:
            from transformers import pipeline

            self.classifier_1 = pipeline(
                "image-classification", model="umm-maybe/AI-image-detector"
            )
            self.classifier_2 = pipeline(
                "image-classification",
                model="dima806/deepfake_vs_real_image_detection",
            )
        except Exception:
            self.classifier_1 = None
            self.classifier_2 = None
        self._models_loaded = True

    @staticmethod
    def generate_hashes(img: Image.Image) -> dict:
        try:
            return {
                "phash": str(imagehash.phash(img)),
                "dhash": str(imagehash.dhash(img)),
                "ahash": str(imagehash.average_hash(img)),
            }
        except Exception as e:
            return {"error": f"Failed to generate hashes: {str(e)}"}

    @staticmethod
    def parse_gps(gps_ifd: dict) -> tuple:

        def convert_dms(dms, ref):
            try:
                deg = float(dms[0])
                mins = float(dms[1])
                secs = float(dms[2])
                dec = deg + (mins / 60.0) + (secs / 3600.0)

                if isinstance(ref, bytes):
                    ref = ref.decode("utf-8", errors="ignore")

                return -dec if str(ref).upper() in ["S", "W"] else dec
            except (TypeError, ValueError, IndexError, ZeroDivisionError):
                return None

        try:
            gps_data = {GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}

            required_keys = [
                "GPSLatitude",
                "GPSLatitudeRef",
                "GPSLongitude",
                "GPSLongitudeRef",
            ]
            if not all(k in gps_data for k in required_keys):
                return None, None

            lat = convert_dms(
                gps_data["GPSLatitude"], gps_data["GPSLatitudeRef"]
            )
            lon = convert_dms(
                gps_data["GPSLongitude"], gps_data["GPSLongitudeRef"]
            )

            if lat is not None and lon is not None:
                return round(lat, 6), round(lon, 6)
            return None, None
        except Exception:
            return None, None

    def parse_metadata(self, image_path: str, img: Image.Image) -> dict:
        parsed_meta = {}
        has_camera_exif = False
        has_png_chunks = False

        width, height = img.size
        parsed_meta["Display_Width_px"] = width
        parsed_meta["Display_Height_px"] = height
        parsed_meta["Aspect_Ratio"] = (
            round(width / height, 2) if height > 0 else 0
        )
        parsed_meta["Color_Mode"] = img.mode
        parsed_meta["File_Format"] = img.format

        file_stat = os.stat(image_path)
        parsed_meta["OS_Created_Time"] = time.ctime(file_stat.st_ctime)
        parsed_meta["OS_Modified_Time"] = time.ctime(file_stat.st_mtime)

        exif_obj = img.getexif()
        if exif_obj:
            exif_ifd = exif_obj.get_ifd(IFD.Exif)
            if exif_ifd:
                has_camera_exif = True
                for tag_id, val in exif_ifd.items():
                    tag_name = TAGS.get(tag_id)
                    if tag_name:
                        parsed_meta[f"EXIF_{tag_name}"] = str(val)

                date_taken = exif_ifd.get(36867) or exif_ifd.get(306)
                if date_taken:
                    parsed_meta["Date_Taken"] = str(date_taken).strip("\x00 ")

            gps_ifd = exif_obj.get_ifd(IFD.GPSInfo)
            if gps_ifd:
                lat, lon = self.parse_gps(gps_ifd)
                if lat is not None and lon is not None:
                    parsed_meta["GPS_Coordinates"] = f"{lat}, {lon}"


        ai_flag = False
        with open(image_path, "rb") as f:
            chunk = f.read(1024 * 1024).lower()
            if any(kw in chunk for kw in AI_KEYWORDS):
                ai_flag = True

        return {
            "exif": parsed_meta,
            "has_exif": has_camera_exif,
            "has_png_chunks": has_png_chunks,
            "has_metadata": len(parsed_meta) > 0,
            "ai_signature_flagged": ai_flag,
        }

    def _extract_model_score(self, classifier, image_path: str) -> float:
        if not classifier:
            return 0.05
        try:
            preds = classifier(image_path)
            for pred in preds:
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

    def analyze(self, image_path: str) -> dict:
        self.load_models()
        with Image.open(image_path) as img:
            hashes = self.generate_hashes(img)
            metadata = self.parse_metadata(image_path, img)

        has_exif = metadata.get("has_exif", False)
        is_png = metadata.get("exif", {}).get("File_Format") == "PNG"
        is_screenshot = is_png and not has_exif

        score1 = self._extract_model_score(self.classifier_1, image_path)
        score2 = self._extract_model_score(self.classifier_2, image_path)
        ai_prob = round((score1 + score2) / 2.0, 2)

        if is_screenshot:
            ai_prob = round(ai_prob * 0.35, 2)

        risk_score = 10
        if not has_exif and not is_screenshot:
            risk_score += 20
        if metadata.get("ai_signature_flagged", False):
            risk_score += 40
        if ai_prob > 0.75:
            risk_score += 35
        elif ai_prob > 0.45:
            risk_score += 15

        return {
            "file_name": os.path.basename(image_path),
            "risk_score": min(risk_score, 100),
            "ai_probability": ai_prob,
            "is_screenshot": is_screenshot,
            "hashes": hashes,
            "metadata": metadata,
        }


_engine = ForensicEngine()


def run_full_analysis(image_path: str) -> dict:
    return _engine.analyze(image_path)