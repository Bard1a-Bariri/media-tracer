import json
import os
from PIL import Image
import streamlit as st

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

        st.subheader(
            f"📄 Analysis for: `{results.get('file_name', uploaded_file.name)}`"
        )

        col1, col2 = st.columns([1, 2])

        with col1:
            st.image(
                Image.open(temp_path),
                caption=results.get("file_name", uploaded_file.name),
                use_container_width=True,
            )

            st.markdown("---")
            st.subheader("Provenance Risk Index")

            risk = results.get("risk_score", 10)
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
                st.warning(
                    "⚠️ Suspicious signatures or unusual pixel patterns detected."
                )
            else:
                st.success("✅ Consistent with authentic capture.")

            st.markdown("---")
            report_json = json.dumps(results, indent=4)
            st.download_button(
                label="📥 Export Forensic Report (JSON)",
                data=report_json,
                file_name=f"forensic_report_{results.get('file_name', uploaded_file.name)}.json",
                mime="application/json",
                key=f"download_{uploaded_file.name}",
            )

        with col2:
            tab1, tab2, tab3 = st.tabs(
                ["Perceptual Hashes", "Metadata & Headers", "Propagation Graph"]
            )

            with tab1:
                st.subheader("Visual Fingerprints")
                st.json(results.get("hashes", {}))
                st.caption(
                    "Perceptual hashes remain stable even if the image is cropped, resized, or re-compressed."
                )

            with tab2:
                st.subheader("Embedded Metadata & Header Analysis")

                metadata = results.get("metadata", {})
                all_meta = metadata.get("exif", {})

                has_camera_exif = metadata.get("has_exif", False)
                has_png_chunks = metadata.get("has_png_chunks", False)

                # Status Banner
                if has_camera_exif:
                    st.success("📷 Camera EXIF Metadata Detected (Hardware Photo)")
                elif has_png_chunks:
                    st.info(
                        "💻 PNG Header Chunks Detected (Software Capture / Screenshot)"
                    )
                else:
                    st.info(
                        "ℹ️ No Camera EXIF or PNG text chunks found. Displaying File System & Display Attributes."
                    )

                # Structural Attributes JSON Output
                if all_meta:
                    st.write("### File Container & Display Attributes")
                    st.json(all_meta)
                else:
                    st.error("Could not parse file metadata structure.")

                # Byte Signature Alert
                if metadata.get("ai_signature_flagged", False):
                    st.error(
                        "🚨 Known synthetic tag (e.g., C2PA, Midjourney, DALL-E) found in raw file bytes!"
                    )

            with tab3:
                st.subheader("Simulated Media Footprint & Network Provenance")

                risk_level = results.get("risk_score", 10)
                is_screenshot = results.get("is_screenshot", False)

                # 1. High Risk / Synthetic AI
                if risk_level >= 70:
                    st.warning(
                        "⚠️ High-risk media detected: Tracing potential synthetic generation and automated spread networks."
                    )
                    mock_edges = [
                        ("Synthetic Generator API", "Anonymous Forum Thread"),
                        ("Anonymous Forum Thread", "Bot Network Alpha"),
                        ("Anonymous Forum Thread", "Bot Network Beta"),
                        ("Bot Network Alpha", "Twitter/X Misinfo Feed"),
                        ("Bot Network Beta", "Telegram Channel"),
                        ("Twitter/X Misinfo Feed", "Target Upload"),
                    ]

                # 2. Software Screenshot / Digital Capture
                elif is_screenshot:
                    st.info("💻 Software screenshot detected: Tracing local display capture lineage.")
                    mock_edges = [
                        ("Display Buffer Render", "OS Screenshot Utility"),
                        ("OS Screenshot Utility", "Local Disk Storage"),
                        ("Local Disk Storage", "Target Upload"),
                    ]

                # 3. Authentic Camera Photo
                else:
                    st.success("🟢 Authentic image profile: Tracing standard media transmission.")
                    mock_edges = [
                        ("Original Camera Sensor", "Device Cloud Sync"),
                        ("Device Cloud Sync", "Direct Messaging Share"),
                        ("Direct Messaging Share", "Target Upload"),
                    ]

                fig = generate_propagation_graph(mock_edges, target_node="Target Upload")
                st.pyplot(fig)