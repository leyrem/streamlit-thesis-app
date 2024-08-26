import streamlit as st

if st.button("Home"):
    st.switch_page("dashboard_app.py")
if st.button("Per Image and Tag Analysis"):
    st.switch_page("pages/per_image_and_tag_analysis.py")
if st.button("Large Scale Analysis"):
    st.switch_page("pages/large_scale_analysis.py")
if st.button("Per Image Name Analysis"):
    st.switch_page("pages/per_image_name_analysis.py")
if st.button("Ground Truth Analysis"):
    st.switch_page("pages/ground_truth_analysis.py")