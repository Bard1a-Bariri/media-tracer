import io
import os
import time
import urllib.parse
from PIL import Image, ImageChops, ImageEnhance, ImageOps
from PIL.ExifTags import GPSTAGS, IFD, TAGS
import imagehash
import numpy as np

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
                # Casing formatted to match app.py requirements
                "pHash": str(imagehash.phash(img)),
                "dHash": str(imagehash.dhash(img)),
                "aHash": str(imagehash.average_hash(img)),
                "wHash": str(imagehash.whash(img)),
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
            "has_metadata": len(parsed_meta) > 0,
            "ai_signature_flagged": ai_flag,
        }

    @staticmethod
    def compute_ela(img: Image.Image, quality: int = 95) -> dict:
        try:
            rgb_img = img.convert("RGB")
            buffer = io.BytesIO()

            rgb_img.save(buffer, format="JPEG", quality=quality)
            buffer.seek(0)

            resaved = Image.open(buffer)
            ela_img = ImageChops.difference(rgb_img, resaved)

            extrema = ela_img.getextrema()
            max_diff = max([ex[1] for ex in extrema])
            scale = 255.0 / max_diff if max_diff > 0 else 1.0
            ela_img = ImageEnhance.Brightness(ela_img).enhance(scale)

            ela_arr = np.array(ela_img)
            mean_diff = float(np.mean(ela_arr))
            std_diff = float(np.std(ela_arr))

            return {
                "ela_mean_diff": round(mean_diff, 2),
                "ela_std_diff": round(std_diff, 2),
                "suspicious_splicing": std_diff > 35.0,
            }
        except Exception as e:
            return {"error": f"ELA failed: {str(e)}"}

    @staticmethod
    def compute_fft_spectral_score(img: Image.Image) -> float:
        try:
            gray = np.array(img.convert("L"), dtype=np.float32)
            f_transform = np.fft.fft2(gray)
            f_shift = np.fft.fftshift(f_transform)
            magnitude_spectrum = 20 * np.log(np.abs(f_shift) + 1e-8)

            rows, cols = gray.shape
            crow, ccol = rows // 2, cols // 2
            radius = min(crow, ccol) // 4

            magnitude_spectrum[
                crow - radius : crow + radius, ccol - radius : ccol + radius
            ] = 0

            return round(float(np.mean(magnitude_spectrum)), 2)
        except Exception:
            return 0.0

    @staticmethod
    def generate_reverse_search_urls(phash_str: str) -> dict:
        encoded_hash = urllib.parse.quote(phash_str)
        return {
            "google_lens": "https://lens.google.com/",
            "tineye": f"https://tineye.com/search?q={encoded_hash}",
            "bing_visual": "https://www.bing.com/visualsearch",
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
        if not os.path.exists(image_path):
            return {"error": "File not found"}

        self.load_models()

        with Image.open(image_path) as img:
            corrected_img = ImageOps.exif_transpose(img)

            hashes = self.generate_hashes(corrected_img)
            metadata = self.parse_metadata(image_path, corrected_img)
            ela_results = self.compute_ela(corrected_img)
            fft_score = self.compute_fft_spectral_score(corrected_img)

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
        if ela_results.get("suspicious_splicing", False):
            risk_score += 15
        if ai_prob > 0.75:
            risk_score += 35
        elif ai_prob > 0.45:
            risk_score += 15

        phash_val = hashes.get("pHash", "")
        reverse_links = self.generate_reverse_search_urls(phash_val)

        return {
            "file_name": os.path.basename(image_path),
            "risk_score": min(risk_score, 100),  # Matched with app.py expectation
            "composite_risk_score": min(risk_score, 100),
            "ai_probability": ai_prob,
            "is_screenshot": is_screenshot,
            "ela_forensics": ela_results,
            "fft_spectral_score": fft_score,
            "hashes": hashes,
            "metadata": metadata,
            "reverse_search_links": reverse_links,
        }


_engine = ForensicEngine()


def run_full_analysis(image_path: str) -> dict:
    return _engine.analyze(image_path)