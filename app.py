import json
import os
import streamlit as st
from PIL import Image
from geopy.geocoders import Nominatim


from engine import run_full_analysis
from network import generate_propagation_graph

st.set_page_config(
    page_title="Media Tracer",
    page_icon="🔍",
    layout="wide",
)

st.title("🔍 Media Tracer: Digital Forensics Dashboard")
st.write(
    "Upload single or batch images to inspect perceptual hashes, extract metadata, and evaluate synthetic media risk."
)

uploaded_files = st.file_uploader(
    "Upload Target Image(s)",
    type=["jpg", "png", "jpeg"],
    accept_multiple_files=True, 
)

if uploaded_files:

    for uploaded_file in uploaded_files:
        temp_path = f"temp_{uploaded_file.name}"

        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        with st.spinner(f"Analyzing {uploaded_file.name}..."):
            results = run_full_analysis(temp_path)

        st.subheader(f"📄 Analysis for: `{results['file_name']}`")

        col1, col2 = st.columns([1, 2])

        with col1:
            st.image(
                Image.open(temp_path),
                caption=results["file_name"],
                use_container_width=True,
            )

            st.markdown("---")
            st.subheader("Provenance Risk Index")

            risk = results["risk_score"]
            st.progress(risk / 100)

            if risk >= 75:
                st.error(f"🔴 HIGH RISK DETECTED ({risk}/100)")
            elif risk >= 40:
                st.warning(f"🟡 MODERATE RISK / UNVERIFIED ({risk}/100)")
            else:
                st.success(f"🟢 LOW RISK / LIKELY AUTHENTIC ({risk}/100)")

            st.markdown("---")
            st.subheader("AI Probability")

            ai_prob = results.get("ai_probability", 0.0)
            ai_pct = int(ai_prob * 100)

            st.metric(label="Pixel Classification Score", value=f"{ai_pct}%")

            if ai_prob > 0.75:
                st.error("🚨 High probability of synthetic / AI generation.")
            elif ai_prob > 0.40:
                st.warning("⚠️ Suspicious signatures or unusual pixel patterns detected.")
            else:
                st.success("✅ Consistent with authentic capture.")

            st.markdown("---")
            report_json = json.dumps(results, indent=4)
            st.download_button(
                label="📥 Export Forensic Report (JSON)",
                data=report_json,
                file_name=f"forensic_report_{results['file_name']}.json",
                mime="application/json",
                key=f"download_{uploaded_file.name}"
            )

        with col2:
            tab1, tab2, tab3 = st.tabs(
                ["Perceptual Hashes", "EXIF & Header Data", "Propagation Graph"]
            )

            with tab1:
                st.subheader("Visual Fingerprints")
                st.json(results["hashes"])
                st.caption(
                    "Perceptual hashes remain stable even if the image is cropped, resized, or re-compressed."
                )

            with tab2:
                st.subheader("Embedded Metadata Analysis")

                metadata = results["metadata"]
                exif_data = metadata.get("exif", {})

                if metadata.get("has_exif", False):
                    gps_key = next((k for k in exif_data if "GPS" in k), None)

                    if gps_key:
                        raw_coords = exif_data[gps_key]
                        try:
                            lat, lon = raw_coords[0], raw_coords[1]
                            geolocator = Nominatim(user_agent="media_tracer_forensics")
                            location = geolocator.reverse((lat, lon), language="en")

                            if location and "address" in location.raw:
                                addr = location.raw["address"]
                                city = (
                                    addr.get("city")
                                    or addr.get("town")
                                    or addr.get("village")
                                    or "Unknown City"
                                )
                                country = addr.get("country", "Unknown Country")

                                exif_data[gps_key] = f"{raw_coords} ({city}, {country})"
                        except Exception:
                            pass

                    with st.expander("📄 Click to Inspect Full EXIF Header Data"):
                        st.json(exif_data)
                else:
                    st.warning("No standard EXIF camera metadata found in file.")

                if metadata.get("ai_signature_flagged", False):
                    st.error(
                        "🚨 Known synthetic tag (e.g., C2PA, Midjourney, DALL-E) found in raw file bytes!"
                    )
            with tab3:
                st.subheader("Simulated Media Footprint")

                mock_edges = [
                    ("Original Domain", "Social Platform A"),
                    ("Social Platform A", "Target Upload"),
                ]

                fig = generate_propagation_graph(
                    mock_edges, target_node="Target Upload"
                )
                st.pyplot(fig)

        st.markdown("---")

        if os.path.exists(temp_path):
            os.remove(temp_path)