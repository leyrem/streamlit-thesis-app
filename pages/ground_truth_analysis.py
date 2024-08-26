import streamlit as st
import pandas as pd
import altair as alt
import plotly.express as px
import json
import numpy as np
import os


def compute_precision(tp, fp):
    if tp + fp == 0:
        return 0

    return tp / (tp+fp)

def compute_recall(tp, fn):
    if tp + fn == 0:
        return 0

    return tp / (tp+fn)

def merge_dicts_sum_values(dict1, dict2):
    # Combine the dictionaries and sum the values for common keys
    merged_dict = {key: dict1.get(key, 0) + dict2.get(key, 0) for key in set(dict1) | set(dict2)}
    return merged_dict

# Page config
st.set_page_config(
    page_title="Docker Image Vulnerability Analysis Dashboard",
    page_icon="🏂",
    layout="wide",
    initial_sidebar_state="expanded")

alt.themes.enable("dark")

#Load data
df_available_images = pd.read_csv('files/images.csv')

# Create dropdown widgets on a sidebar for users  to select data
with st.sidebar:
    st.title('🏂 Docker Image Vulnerability Analysis Dashboard')
    
    # Select an image 
    list_imgs = df_available_images['Image'].tolist()
    
    selected_name = st.selectbox('Select a Docker image', list_imgs, index=len(list_imgs)-1)
    
    file_name = "files/" + selected_name + ".json"
        
    with open(file_name) as file:
        dataJSON = json.load(file)
        
        
results_grype = {
    "False Positive": [],
    "True Positive": [],
    "False Negative": [],
    "True Negative": [],
    "Undetermined": [],
    "FP Reasons": {}
}
results_trivy = {
    "False Positive": [],
    "True Positive": [],
    "False Negative": [],
    "True Negative": [],
    "Undetermined": [],
    "FP Reasons": {}
}
results_jfrog = {
    "False Positive": [],
    "True Positive": [],
    "False Negative": [],
    "True Negative": [],
    "Undetermined": [],
    "FP Reasons": {}
}
results_dockerscout = {
    "False Positive": [],
    "True Positive": [],
    "False Negative": [],
    "True Negative": [],
    "Undetermined": [],
    "FP Reasons": {}
}
results_snyk = {
    "False Positive": [],
    "True Positive": [],
    "False Negative": [],
    "True Negative": [],
    "Undetermined": [],
    "FP Reasons": {}
}

df_stats = pd.DataFrame(columns=[
    'Scanner', 'Number of CVEs found', 
    'True Positives', 'False Positives', 'Undetermined', 'False Negatives', 'False Positive Reasons'])

cves = dataJSON["unique_cves"]

for cve in cves:
    scanners_detected = cve["detected_scanners"].split(',')
    outcome = cve["outcome"]
    cve_id = cve["cve_id"]
    reason_keyword = cve["reason_keyword"]

        
    
    for scanner in scanners_detected:
        scanner = scanner.strip()
        if scanner == "JFrog":
            results_jfrog[outcome].append(cve_id)
            if outcome == "False Positive" and reason_keyword != "":
                if reason_keyword in results_jfrog["FP Reasons"]:
                    results_jfrog["FP Reasons"][reason_keyword] += 1
                else: 
                    results_jfrog["FP Reasons"][reason_keyword] = 1
        elif scanner == "Grype":
            results_grype[outcome].append(cve_id)
            if outcome == "False Positive" and reason_keyword != "":
                if reason_keyword in results_grype["FP Reasons"]:
                    results_grype["FP Reasons"][reason_keyword] += 1
                else: 
                    results_grype["FP Reasons"][reason_keyword] = 1
        elif scanner == "Trivy":
            results_trivy[outcome].append(cve_id)
            if outcome == "False Positive" and reason_keyword != "":
                if reason_keyword in results_trivy["FP Reasons"]:
                    results_trivy["FP Reasons"][reason_keyword] += 1
                else: 
                    results_trivy["FP Reasons"][reason_keyword] = 1
        elif scanner == "Snyk":
            results_snyk[outcome].append(cve_id)
            if outcome == "False Positive" and reason_keyword != "":
                if reason_keyword in results_snyk["FP Reasons"]:
                    results_snyk["FP Reasons"][reason_keyword] += 1
                else: 
                    results_snyk["FP Reasons"][reason_keyword] = 1
        elif scanner == "DockerScout":
            results_dockerscout[outcome].append(cve_id)
            if outcome == "False Positive" and reason_keyword != "":
                if reason_keyword in results_dockerscout["FP Reasons"]:
                    results_dockerscout["FP Reasons"][reason_keyword] += 1
                else: 
                    results_dockerscout["FP Reasons"][reason_keyword] = 1
        else:
            print("UKNOWN SCANNER DETCTED: ", scanner)
        
true_positives_set = set()
true_positives_set.update(results_grype["True Positive"])
true_positives_set.update(results_jfrog["True Positive"])
true_positives_set.update(results_trivy["True Positive"])
true_positives_set.update(results_snyk["True Positive"])
true_positives_set.update(results_dockerscout["True Positive"])

results_snyk["False Negative"] = true_positives_set.difference(set(results_snyk["True Positive"]))
results_grype["False Negative"] = true_positives_set.difference(set(results_grype["True Positive"]))
results_jfrog["False Negative"] = true_positives_set.difference(set(results_jfrog["True Positive"]))
results_trivy["False Negative"] = true_positives_set.difference(set(results_trivy["True Positive"]))
results_dockerscout["False Negative"] = true_positives_set.difference(set(results_dockerscout["True Positive"]))

single_row_g = pd.DataFrame([{
    'Scanner': "Grype", 
    'Number of CVEs found': len(results_grype["Undetermined"]) + len(results_grype["True Positive"]) + len(results_grype["False Positive"]), 
    'True Positives': len(results_grype["True Positive"]),
    'False Positives': len(results_grype["False Positive"]),
    'Undetermined': len(results_grype["Undetermined"]),
    'False Negatives': len(results_grype["False Negative"]),
    'False Positive Reasons': results_grype["FP Reasons"],
}])
df_stats = pd.concat([df_stats, single_row_g], ignore_index=True)

single_row_s = pd.DataFrame([{
    'Scanner': "Snyk", 
    'Number of CVEs found': len(results_snyk["Undetermined"]) + len(results_snyk["True Positive"]) + len(results_snyk["False Positive"]), 
    'True Positives': len(results_snyk["True Positive"]),
    'False Positives': len(results_snyk["False Positive"]),
    'Undetermined': len(results_snyk["Undetermined"]),
    'False Negatives': len(results_snyk["False Negative"]),
    'False Positive Reasons': results_snyk["FP Reasons"],
}])
df_stats = pd.concat([df_stats, single_row_s], ignore_index=True)

single_row_j = pd.DataFrame([{
    'Scanner': "JFrog", 
    'Number of CVEs found': len(results_jfrog["Undetermined"]) + len(results_jfrog["True Positive"]) + len(results_jfrog["False Positive"]), 
    'True Positives': len(results_jfrog["True Positive"]),
    'False Positives': len(results_jfrog["False Positive"]),
    'Undetermined': len(results_jfrog["Undetermined"]),
    'False Negatives': len(results_jfrog["False Negative"]),
    'False Positive Reasons': results_jfrog["FP Reasons"],
}])
df_stats = pd.concat([df_stats, single_row_j], ignore_index=True)

single_row_ds = pd.DataFrame([{
    'Scanner': "DockerScout", 
    'Number of CVEs found': len(results_dockerscout["Undetermined"]) + len(results_dockerscout["True Positive"]) + len(results_dockerscout["False Positive"]), 
    'True Positives': len(results_dockerscout["True Positive"]),
    'False Positives': len(results_dockerscout["False Positive"]),
    'Undetermined': len(results_dockerscout["Undetermined"]),
    'False Negatives': len(results_dockerscout["False Negative"]),
    'False Positive Reasons': results_dockerscout["FP Reasons"],
}])
df_stats = pd.concat([df_stats, single_row_ds], ignore_index=True)

single_row_t = pd.DataFrame([{
    'Scanner': "Trivy", 
    'Number of CVEs found': len(results_trivy["Undetermined"]) + len(results_trivy["True Positive"]) + len(results_trivy["False Positive"]), 
    'True Positives': len(results_trivy["True Positive"]),
    'False Positives': len(results_trivy["False Positive"]),
    'Undetermined': len(results_trivy["Undetermined"]),
    'False Negatives': len(results_trivy["False Negative"]),
    'False Positive Reasons': results_trivy["FP Reasons"],
}])
df_stats = pd.concat([df_stats, single_row_t], ignore_index=True)
  
  

precision_grype = compute_precision(len(results_grype["True Positive"]), len(results_grype["False Positive"]))
precision_trivy = compute_precision(len(results_trivy["True Positive"]), len(results_trivy["False Positive"]))
precision_snyk = compute_precision(len(results_snyk["True Positive"]), len(results_snyk["False Positive"]))
precision_jfrog = compute_precision(len(results_jfrog["True Positive"]), len(results_jfrog["False Positive"]))
precision_ds = compute_precision(len(results_dockerscout["True Positive"]), len(results_dockerscout["False Positive"]))

recall_grype = compute_recall(len(results_grype["True Positive"]), len(results_grype["False Negative"]))
recall_trivy = compute_recall(len(results_trivy["True Positive"]), len(results_trivy["False Negative"]))
recall_snyk = compute_recall(len(results_snyk["True Positive"]), len(results_snyk["False Negative"]))
recall_jfrog = compute_recall(len(results_jfrog["True Positive"]), len(results_jfrog["False Negative"]))
recall_ds = compute_recall(len(results_dockerscout["True Positive"]), len(results_dockerscout["False Negative"]))


tab1, tab2 = st.tabs(["Image Information and Metadata", "Vulnerability Analysis"])

with tab1:
    st.header("Image Information and Metadata")
    st.subheader('Image Category', divider='rainbow')
    cat = value_in_x = df_available_images.loc[df_available_images['Image'] == selected_name, 'Category'].values
    st.write(cat)
    st.subheader('Image Name', divider='rainbow')
    st.write(selected_name)
    
with tab2:
    st.header("Vulnerability Analysis")
    st.subheader("Known unique Vulnerabilities", divider='rainbow')
    st.markdown("*This corresponds to the union of all vulnerabilities found by all scanners*")

    st.metric(label="Known unique vulnerabilities found by all scanners", value=len(cves))
    
    st.write("Vulnerabilities per scanner after ground truth analysis")
    st.dataframe(df_stats)
    
    # --Precision------
    st.markdown(":red[Ratio of True Positives to Known Number of Unique CVEs] by scanner")
        
    precisions = [
        precision_grype, precision_trivy, precision_snyk, precision_jfrog, precision_ds
    ]
    scanners = ["Grype", "Trivy", "Snyk", "JFrog", "Docker Scout"]
    source_precisions_df = pd.DataFrame({"scanners": scanners, "ratio": precisions})


    chart_prec = alt.Chart(source_precisions_df).mark_bar().encode(
        x='ratio:Q',
        y=alt.Y('scanners:N', sort='-x')
    )
    st.altair_chart(chart_prec, theme="streamlit", use_container_width=True)
    #---------------------
    # ---- recall-------
    st.markdown(":red[Ratio of True Positives identified by scanner to all True Positives out of the known unique CVEs]")
        
    recalls = [
        recall_grype, recall_trivy, recall_snyk, recall_jfrog, recall_ds
    ]
    source_rcalls_df = pd.DataFrame({"scanners": scanners, "ratio": recalls})


    chart_rec = alt.Chart(source_rcalls_df).mark_bar().encode(
        x='ratio:Q',
        y=alt.Y('scanners:N', sort='-x')
    )
    st.altair_chart(chart_rec, theme="streamlit", use_container_width=True)
    #--------------
    # ----- chart reasons ---------
    final_reasons_all_scanners = {}
    final_reasons_all_scanners = merge_dicts_sum_values(final_reasons_all_scanners, results_grype["FP Reasons"])
    final_reasons_all_scanners = merge_dicts_sum_values(final_reasons_all_scanners, results_dockerscout["FP Reasons"])
    final_reasons_all_scanners = merge_dicts_sum_values(final_reasons_all_scanners, results_jfrog["FP Reasons"])
    final_reasons_all_scanners = merge_dicts_sum_values(final_reasons_all_scanners, results_snyk["FP Reasons"])
    final_reasons_all_scanners = merge_dicts_sum_values(final_reasons_all_scanners, results_trivy["FP Reasons"])
    
    source_df_reasons = pd.DataFrame({"False Positive Reasons": final_reasons_all_scanners.keys(), "Count": final_reasons_all_scanners.values()})
    chart_dist_fp_reasons = alt.Chart(source_df_reasons).mark_bar().encode(
        x='False Positive Reasons:O',
        y="Count:Q",
        color=alt.Color(field="False Positive Reasons", type="nominal"),
    ).properties(
        width=50,
        height = 500,
        title='Reasons for False Positives across all scanners'
    )
    st.altair_chart(chart_dist_fp_reasons, theme="streamlit", use_container_width=True)
    
    
    #-----------------------
            
    tab2_1, tab2_2 = st.tabs(["Detailed Unique Vulnerabilities", ""]) 
    with tab2_1:
        for cve in cves:
            scanners_detected = cve["detected_scanners"].split(',')
            outcome = cve["outcome"]
            cve_id = cve["cve_id"]
            reason = cve["reason"]
            
            
            st.markdown("**:red["+cve_id+"]**")
                    
            with st.expander("See detailed analysis"):
                st.write("Detected by the following scanners: " + cve["detected_scanners"])
                st.markdown("This CVE is a: **:red[" + outcome + "]**")
                if reason != "":
                    st.write("Reason: " +  reason)
                    st.write("Reason category: " +  cve["reason_keyword"])
                
        