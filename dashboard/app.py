# dashboard/app.py - Streamlit SOC Visualization Dashboard
import streamlit as st

st.set_page_config(
    page_title="ThreatLens SOC Dashboard",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("ThreatLens SOC Dashboard")
st.write("Welcome to your local Security Operations Center. Real-time alert analysis and visualization dashboard.")
st.info("System setup is complete. Day 1 setup is successful.")
