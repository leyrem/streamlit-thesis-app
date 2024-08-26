import streamlit as st
import pandas as pd
import altair as alt
import json
import glob
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
import itertools
import numpy as np

GENERAL_STATS_OFFICIAL = 'files/general_stats_Official_Images.json'
GENERAL_STATS_VERIFIED = 'files/general_stats_Verified_Images.json'
GENERAL_STATS_SPONSORED = 'files/general_stats_Sponsored_Images.json'
GENERAL_STATS_ALL = 'files/general_stats_All_Images.json'

DATA_RESULTS_OFFICIAL = 'files/data_results_Official_Images.json'
DATA_RESULTS_VERIFIED = 'files/data_results_Verified_Images.json'
DATA_RESULTS_SPONSORED = 'files/data_results_Sponsored_Images.json'
DATA_RESULTS_ALL = 'files/data_results_All_Images.json'

CVES_FREQ_OFFICIAL = 'files/cves_freq_sorted_df_Official_Images.csv'
CVES_FREQ_VERIFIED = 'files/cves_freq_sorted_df_Verified_Images.csv'
CVES_FREQ_SPONSORED = 'files/cves_freq_sorted_df_Sponsored_Images.csv'
CVES_FREQ_ALL = 'files/cves_freq_sorted_df_All_Images.csv'

PKGS_FREQ_OFFICIAL = 'files/pkgs_freq_df_Official_Images.csv'
PKGS_FREQ_VERIFIED = 'files/pkgs_freq_df_Verified_Images.csv'
PKGS_FREQ_SPONSORED = 'files/pkgs_freq_df_Sponsored_Images.csv'
PKGS_FREQ_ALL = 'files/pkgs_freq_df_All_Images.csv'

IMAGES_STATS_OFFICIAL = 'files/df_images_stats_Official_Images.csv'
IMAGES_STATS_SPONSORED ='files/df_images_stats_Sponsored_Images.csv'
IMAGES_STATS_VERIFIED =  'files/df_images_stats_Verified_Images.csv'
IMAGES_STATS_ALL = 'files/df_images_stats_All_Images.csv'

data_stats = None
data_cves_df = pd.DataFrame()
data_results = None

# Page config
st.set_page_config(
    page_title="Docker Large Scale Image Vulnerability Analysis Dashboard",
    page_icon="🏂",
    layout="wide",
    initial_sidebar_state="expanded")

alt.themes.enable("dark")

# Create dropdown widgets on a sidebar for users to select data
with st.sidebar:
    st.title('🏂 Docker Large Scale Image Vulnerability Analysis Dashboard')

    # Select a image repo name
    image_name_list = ["All Images", "Verified Images", "Sponsored Images", "Official Images"]
    selected_name = st.selectbox('Select a set of Docker images', image_name_list, index=len(image_name_list)-1)

    file_path_stats = ""
    file_path_results = ""
    file_path_cves_freq = ""
    file_path_pkgs_freq = ""
    file_path_images_stats = ""
    if selected_name == "All Images":
        file_path_stats = GENERAL_STATS_ALL
        file_path_results = DATA_RESULTS_ALL
        file_path_cves_freq = CVES_FREQ_ALL
        file_path_pkgs_freq = PKGS_FREQ_ALL
        file_path_images_stats = IMAGES_STATS_ALL
    elif selected_name == "Sponsored Images":
        file_path_stats = GENERAL_STATS_SPONSORED
        file_path_results = DATA_RESULTS_SPONSORED
        file_path_cves_freq = CVES_FREQ_SPONSORED
        file_path_pkgs_freq = PKGS_FREQ_SPONSORED
        file_path_images_stats = IMAGES_STATS_SPONSORED
    elif selected_name == "Official Images":
        file_path_stats = GENERAL_STATS_OFFICIAL
        file_path_results = DATA_RESULTS_OFFICIAL
        file_path_cves_freq = CVES_FREQ_OFFICIAL
        file_path_pkgs_freq = PKGS_FREQ_OFFICIAL
        file_path_images_stats = IMAGES_STATS_OFFICIAL
    elif selected_name == "Verified Images":
        file_path_stats = GENERAL_STATS_VERIFIED
        file_path_results = DATA_RESULTS_VERIFIED
        file_path_cves_freq = CVES_FREQ_VERIFIED
        file_path_pkgs_freq = PKGS_FREQ_VERIFIED
        file_path_images_stats = IMAGES_STATS_VERIFIED
        
    # Load Data
    with open(file_path_stats, 'r') as file:
        data_stats = json.load(file)
        
    with open(file_path_results, 'r') as file2:
        data_results = json.load(file2)
        
    data_cves_df = pd.read_csv(file_path_cves_freq)
    pkgs_freq_df = pd.read_csv(file_path_pkgs_freq)
    df_images_stats = pd.read_csv(file_path_images_stats)
    
                
tab1, tab2 = st.tabs(["Images Information and Metadata", "Vulnerability Analysis"])

with tab1:
    st.header("Images Information")

    st.metric(label = "Number of Docker images analysed", value=data_stats["number_images_analysed"])
    
    st.write("Images Vulnerability Distribution and Metadata")
    st.dataframe(df_images_stats)
    
    subcategories_dict = {}
    subcategories_dict_scores = {}
    subcategories_dict_nums = {}
    
    for ind, row in df_images_stats.iterrows():
        if not pd.isnull(row['SubCategories']):
            subcategories = row['SubCategories'].split('/')
            for sub in subcategories:
                if sub in subcategories_dict:
                    subcategories_dict[sub].append(row['Number of unique CVEs'])
                else:
                    subcategories_dict[sub] = [row['Number of unique CVEs']]
                
    for key, value in subcategories_dict.items():
        num_images = len(value)
        values_arr = np.array(value)
        average_cves_per_image_sub = np.mean(values_arr).item()
        subcategories_dict_scores[key] = round(average_cves_per_image_sub,2)
        subcategories_dict_nums[key] = num_images
    
    source_dist_subcategories_num = pd.DataFrame({"subcategories": subcategories_dict_nums.keys(), "Number of Images": subcategories_dict_nums.values()})
    chart_dist_subcategories_num = alt.Chart(source_dist_subcategories_num).mark_bar().encode(
        x='subcategories:O',
        y="Number of Images:Q",
        color=alt.Color(field="subcategories", type="nominal"),
    ).properties(
        width=200,
        height = 500,
        title='Number of Images in each subcategory'
    )
    st.altair_chart(chart_dist_subcategories_num, theme="streamlit", use_container_width=True)
    
    #-----------------------------------

    st.write("Correlation Graphs")
    
    chartd = alt.Chart(df_images_stats).mark_point().encode(
        x='Number of unique CVEs:Q',
        y='Number of Pulls:Q',
        color='Category:N',
        tooltip=['Image and Tag Name', 'Number of unique CVEs', 'Number of Pulls']
    ).properties(
        title='Number of Pulls vs. Number of CVEs'
    ).interactive()
    
    st.altair_chart(chartd, theme="streamlit", use_container_width=True)
    correlation_coefficient_pulls = round(df_images_stats['Number of unique CVEs'].corr(df_images_stats['Number of Pulls']),2)
    st.metric(label="Correlation Coeff: Pulls vs. CVEs", value=correlation_coefficient_pulls)
    
    chartf = alt.Chart(df_images_stats).mark_point().encode(
        x='Number of unique CVEs:Q',
        y='Number of Repo Stars:Q',
        color='Category:N',
        tooltip=['Image and Tag Name', 'Number of unique CVEs', 'Number of Repo Stars']
    ).properties(
        title='Number of Repo Stars vs. Number of CVEs'
    ).interactive()
    
    st.altair_chart(chartf, theme="streamlit", use_container_width=True)
    correlation_coefficient_stars = round(df_images_stats['Number of unique CVEs'].corr(df_images_stats['Number of Repo Stars']),2)
    st.metric(label="Correlation Coeff: Stars vs. CVEs", value=correlation_coefficient_stars)

    
    chart_size = alt.Chart(df_images_stats).mark_point().encode(
        x='Number of unique CVEs:Q',
        y='Size:Q',
        color='Category:N',
        tooltip=['Image and Tag Name', 'Number of unique CVEs', 'Size']
    ).properties(
        title='Image Size vs. Number of CVEs'
    ).interactive()
    
    st.altair_chart(chart_size, theme="streamlit", use_container_width=True)
    correlation_coefficient_size = round(df_images_stats['Number of unique CVEs'].corr(df_images_stats['Size']),2)
    st.metric(label="Correlation Coeff: Size vs. CVEs", value=correlation_coefficient_size)



with tab2:
    st.header("Vulnerability Analysis")
    
    tab2_1, tab2_2, tab2_3 = st.tabs(["Overall Vulnerability Landscape", "Detailed Unique Vulnerabilities", "Scanner Performance Analysis"])
    
    with tab2_2:
        # -----------------SHOW cves freq dataframe----------------------------
        st.write("Dataframe with the specific detected information per CVE ID")
        st.dataframe(data_cves_df)
        #------------------------------
    with tab2_1:
        st.subheader("Overall Vulnerability Landscape", divider='rainbow')
        
        st.metric(label = "Number of Docker images analysed", value=data_results["number_images_analysed"])
        
        if selected_name == "All Images":
            col1, col2, col3 = st.columns(3)
                 
            col1.metric(label ="Number of Official Images analysed", value=689)
            col2.metric(label ="Number of Verified Images analysed", value=702)
            col3.metric(label ="Number of Sponsored Images analysed", value=712)
            
        st.metric(label = "Number of total unique vulnerabilities found by all scanners", value=data_results["num_unique_vulnerabilities"])
        
        # -------- DONUT CHART WITH SEVERITY DISTRIBUTION
        st.write(" ")
        st.write("Severity Distribution of Vulnerabilities")
        categories = ["LOW VULNERABILITIES", "MEDIUM VULNERABILITIES", "HIGH VULNERABILITIES", "CRITICAL VULNERABILITIES", "UNASSIGNED VULNERABILITIES", "DIFFERING VULNERABILITIES"]
        values = [
            data_results["low_vulnerabilities"], 
            data_results["medium_vulnerabilitites"],
            data_results["high_vulnerabilities"],
            data_results["critical_vulnerabilitites"],
            data_results["unassigned_vulnerabilities"],
            data_results["differing_vulnerabilitites"],
        ]
        source = pd.DataFrame({"category": categories, "value": values})

        chart = alt.Chart(source).mark_arc(innerRadius=50).encode(
            theta=alt.Theta(field="value", type="quantitative"),
            color=alt.Color(field="category", type="nominal"),
        )
        st.altair_chart(chart, theme=None, use_container_width=True)
        # ----------------------
        #-------- Severity Distribution -----
        tot = data_results["num_unique_vulnerabilities"]
        col1, col2, col3 = st.columns(3)
                 
        col1.metric(label ="Number of LOW vulnerabilities", value=str(values[0]) + ' (' + str(round(values[0] / tot * 100, 1)) + '%)')
        col2.metric(label ="Number of MEDIUM vulnerabilities", value=str(values[1]) + ' (' + str(round(values[1] / tot * 100, 1)) + '%)')
        col3.metric(label ="Number of HIGH vulnerabilities", value=str(values[2]) + ' (' + str(round(values[2] / tot * 100, 1)) + '%)')
            
        col4, col5, col6 = st.columns(3)
                 
        col4.metric(label ="Number of CRITICAL vulnerabilities", value=str(values[3]) + ' (' + str(round(values[3] / tot * 100, 1)) + '%)')
        col5.metric(label ="Number of UNASSIGNED vulnerabilities", value=str(values[4]) + ' (' + str(round(values[4] / tot * 100, 1)) + '%)')
        col6.metric(label ="Number of DIFFERING vulnerabilities", value=str(values[5]) + ' (' + str(round(values[5] / tot * 100, 1)) + '%)')
        # -----------------------------------------
        # -------- DONUT CHART WITH fix DISTRIBUTION
        
        st.write(" ")
        st.write("Fix Status Distribution of Vulnerabilities")
        categories2 = ["FIXED VULNERABILITIES", "NOT FIXED VULNERABILITIES", "DIFFERENT STATUSES REPORTED VULNERABILITIES"]
        values2 = [
            data_results["fixed_vulnerabilities"], 
            data_results["not_fixed_vulnerabilities"],
            data_results["vulnerabilities_different_fix_status"],
        ]
        source2 = pd.DataFrame({"category": categories2, "value": values2})

        chart2 = alt.Chart(source2).mark_arc(innerRadius=50).encode(
            theta=alt.Theta(field="value", type="quantitative"),
            color=alt.Color(field="category", type="nominal"),
        )
        st.altair_chart(chart2, theme=None, use_container_width=True)
        # ----------------------
        #-------- fix Distribution -----
        col1, col2, col3 = st.columns(3)
                 
        col1.metric(label ="Number of FIXED vulnerabilities", value=str(values2[0]) + ' (' + str(round(values2[0] / tot * 100, 1)) + '%)')
        col2.metric(label ="Number of NOT FIXED vulnerabilities", value=str(values2[1]) + ' (' + str(round(values2[1] / tot * 100, 1)) + '%)')
        col3.metric(label ="Number of vulnerabilities with DIFFERENT (fix) statuses reported", value=str(values2[2]) + ' (' + str(round(values2[2] / tot * 100, 1)) + '%)')
        # -----------------------------------------
        # -------- CVEs images analysis ----------------
        st.markdown("General landscape of vulnerabilities in :red[all images analysed]")
        col1, col2, col3 = st.columns(3)
        col1.metric(label ="Average number of CVEs per image", value=round(data_stats["average_cves_per_image"], 2))
        col2.metric(label ="Median number of CVEs per image", value=data_stats["median_cves_per_image"])
        col3.metric(label ="Variance in the number of CVEs per image", value=round(data_stats["variance_cves_per_image"], 2))
            
        col4, col5 = st.columns(2)
        col4.metric(label ="Min number of CVEs found in an image", value=data_stats["min_value_cves_per_images"])
        col5.metric(label ="Max number of CVEs found in an image", value=data_stats["max_value_cves_per_image"])
        # --------------------------------
        # ------ dist per subcategory
        source_dist_subcategories = pd.DataFrame({"subcategories": subcategories_dict_scores.keys(), "Avg CVEs per Image": subcategories_dict_scores.values()})
        chart_dist_subcategories = alt.Chart(source_dist_subcategories).mark_bar().encode(
            x='subcategories:O',
            y="Avg CVEs per Image:Q",
            color=alt.Color(field="subcategories", type="nominal"),
        ).properties(
            width=200,
            height = 500,
            title='Average Number of CVEs per image across all scanners per subcategories'
        )
        st.altair_chart(chart_dist_subcategories, theme="streamlit", use_container_width=True)
        #–-----------------------
        
        # -------- DONUT CHART WITH cvss scores DISTRIBUTION
        
        st.write(" ")
        st.write("CVSS V3 Scores Distribution of Vulnerabilities")
        categories3 = ["VULNERABILITIES WITH AGREED CVSS V3 SCORE", "VULNERABILITIES WITH NO CVSS V3 SCORE ASSIGNED", "VULNERABILITIES WITH DIFFERENT CVSS V3 SCORES ASSIGNED"]
        values3 = [
            data_results["vulnerabilites_agreed_upon_cvss_score"], 
            data_results["vulnerabilities_no_cvss_score"],
            data_results["vulnerabilities_different_cvss_scores"],
        ]
        source3 = pd.DataFrame({"category": categories3, "value": values3})

        chart3 = alt.Chart(source3).mark_arc(innerRadius=50).encode(
            theta=alt.Theta(field="value", type="quantitative"),
            color=alt.Color(field="category", type="nominal"),
        )
        st.altair_chart(chart3, theme=None, use_container_width=True)
        # ----------------------
        #-------- CVSS SCORES Distribution -----
        col11, col21, col31 = st.columns(3)
                 
        col11.metric(label ="Vulnerabilities with an agreed CVSS V3 Score across all scanners", value=str(values3[0]) + ' (' + str(round(values3[0] / tot * 100, 1)) + '%)')
        col21.metric(label ="Vulnerabilities with no CVSS V3 Score across all scanners", value=str(values3[1]) + ' (' + str(round(values3[1] / tot * 100, 1)) + '%)')
        col31.metric(label ="Vulnerabilities with different CVSS V3 Scores reported across all scanners", value=str(values3[2]) + ' (' + str(round(values3[2] / tot * 100, 1)) + '%)')
        # -----------------------------------------
        
        st.metric(label="Average CVSS V3 Score across CVEs with an agreed-upon score", value=data_results["average_cvss_score_per_vuln"])
        
         #---------TYPES DIST-----
        type_dict = data_results["type_of_vulnerabilities_dict"]
        source_dist_types = pd.DataFrame({"Vulnerability Types": type_dict.keys(), "Number CVEs": type_dict.values()})
        chart_dist_types = alt.Chart(source_dist_types).mark_bar().encode(
            x='Vulnerability Types:O',
            y="Number CVEs:Q",
            color=alt.Color(field="Vulnerability Types", type="nominal"),
        ).properties(
            width=200,
            height = 500,
            title='Number of CVEs in each vulnerability type across ALL scanners'
        )
        st.altair_chart(chart_dist_types, theme="streamlit", use_container_width=True)
        
        for k, v in type_dict.items():
            print("key2: ", k)
            print("val2: ", v)
        #-----------------
        
        # ---PKGS FREQ ------------------
        st.write("Dataframe with the unique packages affecting the unique CVEs and their counts (how many CVEs they affect)")
        st.dataframe(pkgs_freq_df)
        
    with tab2_3:
        
        # ------ Number of CVES found by scanner graph-------
        st.markdown("Number of :red[CVEs] found by scanner")
        
        scanners = ["Snyk", "Trivy", "Grype", "DockerScout", "JFrog"]
        values_cves_found = [
            data_results["Snyk_results"]["num_CVES_detected"],
            data_results["Trivy_results"]["num_CVES_detected"],
            data_results["Grype_results"]["num_CVES_detected"],
            data_results["DockerScout_results"]["num_CVES_detected"],
            data_results["JFrog_results"]["num_CVES_detected"],
        ]
        
        source_dist_scanners = pd.DataFrame({"scanners": scanners, "values": values_cves_found})
        chart_dist_cvess = alt.Chart(source_dist_scanners).mark_bar().encode(
            x='scanners:O',
            y="values:Q",
            color=alt.Color(field="scanners", type="nominal"),
        ).properties(width=100)
        st.altair_chart(chart_dist_cvess, theme="streamlit", use_container_width=True)
        #------------------
         # ------ Average number of CVEs per image found by scanner graph-------
        st.markdown("Average number of :red[CVEs per image] found by scanner")
        
        avg_values_cves_found = [
            round(data_results["Snyk_results"]["average_cves"], 2),
            round(data_results["Trivy_results"]["average_cves"], 2),
            round(data_results["Grype_results"]["average_cves"], 2),
            round(data_results["DockerScout_results"]["average_cves"], 2),
            round(data_results["JFrog_results"]["average_cves"], 2),
        ]
        
        source_dist_avg_scanners = pd.DataFrame({"scanners": scanners, "values": avg_values_cves_found})
        chart_dist_cvess_avg = alt.Chart(source_dist_avg_scanners).mark_bar().encode(
            x='scanners:O',
            y="values:Q",
            color=alt.Color(field="scanners", type="nominal"),
        ).properties(width=100)
        st.altair_chart(chart_dist_cvess_avg, theme="streamlit", use_container_width=True)
        #-----------------
        
        # --------------severities per scanner------------------
        sev_per_scanner = {
            "Snyk_results": {
                "low_vulns": data_results["Snyk_results"]["low_vulns"], 
                "medium_vulns": data_results["Snyk_results"]["medium_vulns"],  
                "high_vulns": data_results["Snyk_results"]["high_vulns"],
                "critical_vulns": data_results["Snyk_results"]["critical_vulns"],
                "unassigned_vulns": data_results["Snyk_results"]["unassigned_vulns"],  
            },
            "Trivy_results": {
                "low_vulns": data_results["Trivy_results"]["low_vulns"], 
                "medium_vulns": data_results["Trivy_results"]["medium_vulns"],  
                "high_vulns": data_results["Trivy_results"]["high_vulns"],
                "critical_vulns": data_results["Trivy_results"]["critical_vulns"],
                "unassigned_vulns": data_results["Trivy_results"]["unassigned_vulns"], 
            },
            "Grype_results": {
                "low_vulns": data_results["Grype_results"]["low_vulns"], 
                "medium_vulns": data_results["Grype_results"]["medium_vulns"],  
                "high_vulns": data_results["Grype_results"]["high_vulns"],
                "critical_vulns": data_results["Grype_results"]["critical_vulns"],
                "unassigned_vulns": data_results["Grype_results"]["unassigned_vulns"], 
            },
            "DockerScout_results": {
                "low_vulns": data_results["DockerScout_results"]["low_vulns"], 
                "medium_vulns": data_results["DockerScout_results"]["medium_vulns"],  
                "high_vulns": data_results["DockerScout_results"]["high_vulns"],
                "critical_vulns": data_results["DockerScout_results"]["critical_vulns"],
                "unassigned_vulns": data_results["DockerScout_results"]["unassigned_vulns"], 
            },
            "JFrog_results": {
                "low_vulns": data_results["JFrog_results"]["low_vulns"], 
                "medium_vulns": data_results["JFrog_results"]["medium_vulns"],  
                "high_vulns": data_results["JFrog_results"]["high_vulns"],
                "critical_vulns": data_results["JFrog_results"]["critical_vulns"],
                "unassigned_vulns": data_results["JFrog_results"]["unassigned_vulns"], 
            }
        }
        
        # Prepare data for the stacked bar chart
        data_sev_by_scanner = []
        for scanner in scanners:
            scanner_results = sev_per_scanner[f"{scanner}_results"]
            for var in ["low_vulns", "medium_vulns", "high_vulns", "critical_vulns", "unassigned_vulns"]:
                data_sev_by_scanner.append({"scanner": scanner, "variable": var, "value": scanner_results[var]})

        # Create DataFrame
        source_df_sev_by_scanner = pd.DataFrame(data_sev_by_scanner)
        
        chart_sev_by_scanner = alt.Chart(source_df_sev_by_scanner).mark_bar(size=15).encode(
            x=alt.X('scanner:N', title='Scanner', axis=alt.Axis(labelAngle=-90, labelFontSize=10, labelOverlap=False)),
            y=alt.Y('value:Q', title='Number of Vulnerabilities'),
            color='variable:N',
            column=alt.Column('variable:N', title='Severity', header=alt.Header(labelAngle=-45))
        ).properties(
            title="Vulnerabilities by Severity for Each Scanner",
            width=80  # Smaller width for even narrower bars
        ).configure_facet(
            spacing=20  # No spacing between facets
        ).configure_title(
            anchor='start'
        )

        st.altair_chart(chart_sev_by_scanner, theme="streamlit", use_container_width=False)
        #----------------
        
        # --------------fix per scanner------------------
        fix_per_scanner = {
            "Snyk_results": {
                "fixed_vulns": data_results["Snyk_results"]["fixed_vulns"], 
                "not_fixed_vulns": data_results["Snyk_results"]["not_fixed_vulns"], 
            },
            "Trivy_results": {
                "fixed_vulns": data_results["Trivy_results"]["fixed_vulns"], 
                "not_fixed_vulns": data_results["Trivy_results"]["not_fixed_vulns"],
            },
            "Grype_results": {
                "fixed_vulns": data_results["Grype_results"]["fixed_vulns"], 
                "not_fixed_vulns": data_results["Grype_results"]["not_fixed_vulns"],
            },
            "DockerScout_results": {
                "fixed_vulns": data_results["DockerScout_results"]["fixed_vulns"], 
                "not_fixed_vulns": data_results["DockerScout_results"]["not_fixed_vulns"],
            },
            "JFrog_results": {
                "fixed_vulns": data_results["JFrog_results"]["fixed_vulns"], 
                "not_fixed_vulns": data_results["JFrog_results"]["not_fixed_vulns"],
            }
        }
        
        # Prepare data for the stacked bar chart
        data_fix_by_scanner = []
        for scanner in scanners:
            scanner_results = fix_per_scanner[f"{scanner}_results"]
            for var in ["fixed_vulns", "not_fixed_vulns"]:
                data_fix_by_scanner.append({"scanner": scanner, "variable": var, "value": scanner_results[var]})

        # Create DataFrame
        source_df_fix_by_scanner = pd.DataFrame(data_fix_by_scanner)
        
        chart_fix_by_scanner = alt.Chart(source_df_fix_by_scanner).mark_bar(size=15).encode(
            x=alt.X('scanner:N', title='Scanner', axis=alt.Axis(labelAngle=-90, labelFontSize=10, labelOverlap=False)),
            y=alt.Y('value:Q', title='Number of Vulnerabilities'),
            color='variable:N',
            column=alt.Column('variable:N', title='Fix Status', header=alt.Header(labelAngle=-45))
        ).properties(
            title="Vulnerabilities by Fix Status for Each Scanner",
            width=80  # Smaller width for even narrower bars
        ).configure_facet(
            spacing=20  # No spacing between facets
        ).configure_title(
            anchor='start'
        )

        st.altair_chart(chart_fix_by_scanner, theme="streamlit", use_container_width=False)
        #----------------
        
        # --------------CVSS scores per scanner------------------
        cvss_per_scanner = {
            "Snyk_results": {
                "vulns_with_assigned_cvss_score": data_results["Snyk_results"]["cvss_vulns"], 
                "vulns_with_no_assigned_cvss_score": data_results["Snyk_results"]["no_cvss_vulns"], 
            },
            "Trivy_results": {
                "vulns_with_assigned_cvss_score": data_results["Trivy_results"]["cvss_vulns"], 
                "vulns_with_no_assigned_cvss_score": data_results["Trivy_results"]["no_cvss_vulns"],
            },
            "Grype_results": {
                "vulns_with_assigned_cvss_score": data_results["Grype_results"]["cvss_vulns"], 
                "vulns_with_no_assigned_cvss_score": data_results["Grype_results"]["no_cvss_vulns"],
            },
            "DockerScout_results": {
                "vulns_with_assigned_cvss_score": data_results["DockerScout_results"]["cvss_vulns"], 
                "vulns_with_no_assigned_cvss_score": data_results["DockerScout_results"]["no_cvss_vulns"],
            },
            "JFrog_results": {
                "vulns_with_assigned_cvss_score": data_results["JFrog_results"]["cvss_vulns"], 
                "vulns_with_no_assigned_cvss_score": data_results["JFrog_results"]["no_cvss_vulns"],
            }
        }
        
        # Prepare data for the stacked bar chart
        data_cvss_by_scanner = []
        for scanner in scanners:
            scanner_results = cvss_per_scanner[f"{scanner}_results"]
            for var in ["vulns_with_assigned_cvss_score", "vulns_with_no_assigned_cvss_score"]:
                data_cvss_by_scanner.append({"scanner": scanner, "variable": var, "value": scanner_results[var]})

        # Create DataFrame
        source_df_cvss_by_scanner = pd.DataFrame(data_cvss_by_scanner)
        
        chart_cvss_by_scanner = alt.Chart(source_df_cvss_by_scanner).mark_bar(size=15).encode(
            x=alt.X('scanner:N', title='Scanner', axis=alt.Axis(labelAngle=-90, labelFontSize=10, labelOverlap=False)),
            y=alt.Y('value:Q', title='Number of Vulnerabilities'),
            color='variable:N',
            column=alt.Column('variable:N', title='CVSS V3 Scores', header=alt.Header(labelAngle=-45))
        ).properties(
            title="Vulnerabilities by CVSS V3 Scores Status for Each Scanner",
            width=80  # Smaller width for even narrower bars
        ).configure_facet(
            spacing=20  # No spacing between facets
        ).configure_title(
            anchor='start'
        )

        st.altair_chart(chart_cvss_by_scanner, theme="streamlit", use_container_width=False)
        #----------------
        
        # ------ Average CVSS V3 score by scanner graph-------
        st.markdown("Average :red[CVSS V3 Score] per CVE by scanner")
        
        avg_cvss_found = [
            data_results["Snyk_results"]["avg_cvss"],
            data_results["Trivy_results"]["avg_cvss"],
            data_results["Grype_results"]["avg_cvss"],
            data_results["DockerScout_results"]["avg_cvss"],
            data_results["JFrog_results"]["avg_cvss"],
        ]
        source_dist_avg_cvss_scanners = pd.DataFrame({"scanners": scanners, "values": avg_cvss_found})


        chart_cvss = alt.Chart(source_dist_avg_cvss_scanners).mark_bar().encode(
            x='values:Q',
            y=alt.Y('scanners:N', sort='-x')
        )

        st.altair_chart(chart_cvss, theme="streamlit", use_container_width=True)
        #------------------
        
        # ------ Average efficacy by scanner graph-------
        st.markdown("Average :red[comparative efficacy] by scanner")
        
        avg_effic_found = [
            data_results["Snyk_results"]["average_efficacy"],
            data_results["Trivy_results"]["average_efficacy"],
            data_results["Grype_results"]["average_efficacy"],
            data_results["DockerScout_results"]["average_efficacy"],
            data_results["JFrog_results"]["average_efficacy"],
        ]
        source_dist_avg_effic_scanners = pd.DataFrame({"scanners": scanners, "values": avg_effic_found})


        chart_effic = alt.Chart(source_dist_avg_effic_scanners).mark_bar().encode(
            x='values:Q',
            y=alt.Y('scanners:N', sort='-x')
        )

        st.altair_chart(chart_effic, theme="streamlit", use_container_width=True)
        #------------------
        
        # ------------------ pkgs affected per scanner ----------------
        df_snyk_pkgs = pd.DataFrame(list(data_results["Snyk_results"]["pkgs_affected_dict"].items()), columns=['Package', 'Count'])
        df_trivy_pkgs = pd.DataFrame(list(data_results["Trivy_results"]["pkgs_affected_dict"].items()), columns=['Package', 'Count'])
        df_grype_pkgs = pd.DataFrame(list(data_results["Grype_results"]["pkgs_affected_dict"].items()), columns=['Package', 'Count'])
        df_docS_pkgs = pd.DataFrame(list(data_results["DockerScout_results"]["pkgs_affected_dict"].items()), columns=['Package', 'Count'])
        df_jfrog_pkgs = pd.DataFrame(list(data_results["JFrog_results"]["pkgs_affected_dict"].items()), columns=['Package', 'Count'])
        
        col1, col2, col3 = st.columns(3)
        col1.write("Snyk Packages Count")
        col1.dataframe(df_snyk_pkgs)
        col2.write("Trivy Packages Count")
        col2.dataframe(df_trivy_pkgs)
        col3.write("Grype Packages Count")
        col3.dataframe(df_grype_pkgs)
        
        col4, col5 = st.columns(2)
        col4.write("DockerScout Packages Count")
        col4.dataframe(df_docS_pkgs)
        col5.write("JFrog Packages Count")
        col5.dataframe(df_jfrog_pkgs)
        
        # ---------
            
        with st.expander("Snyk detailed analysis results"):
            #-------- CVEs Distribution -----
            col1, col2, col3 = st.columns(3)
            col1.metric(label ="Average number of CVEs per image", value=round(data_results["Snyk_results"]["average_cves"], 2))
            col2.metric(label ="Median number of CVEs per image", value=data_results["Snyk_results"]["median_cves"])
            col3.metric(label ="Variance in the number of CVEs per image", value=round(data_results["Snyk_results"]["variance_cves"], 2))
                
            col4, col5 = st.columns(2)
            col4.metric(label ="Min number of CVEs found in an image", value=data_results["Snyk_results"]["min_cves"])
            col5.metric(label ="Max number of CVEs found in an image", value=data_results["Snyk_results"]["max_cves"])
            # -----------------------------------------
            
        with st.expander("Trivy detailed analysis results"):
            #-------- CVEs Distribution -----
            col1, col2, col3 = st.columns(3)
            col1.metric(label ="Average number of CVEs per image", value=round(data_results["Trivy_results"]["average_cves"], 2))
            col2.metric(label ="Median number of CVEs per image", value=data_results["Trivy_results"]["median_cves"])
            col3.metric(label ="Variance in the number of CVEs per image", value=round(data_results["Trivy_results"]["variance_cves"], 2))
                
            col4, col5 = st.columns(2)
            col4.metric(label ="Min number of CVEs found in an image", value=data_results["Trivy_results"]["min_cves"])
            col5.metric(label ="Max number of CVEs found in an image", value=data_results["Trivy_results"]["max_cves"])
            # -----------------------------------------
        
        with st.expander("Grype detailed analysis results"):
            #-------- CVEs Distribution -----
            col1, col2, col3 = st.columns(3)
            col1.metric(label ="Average number of CVEs per image", value=round(data_results["Grype_results"]["average_cves"], 2))
            col2.metric(label ="Median number of CVEs per image", value=data_results["Grype_results"]["median_cves"])
            col3.metric(label ="Variance in the number of CVEs per image", value=round(data_results["Grype_results"]["variance_cves"], 2))
                
            col4, col5 = st.columns(2)
            col4.metric(label ="Min number of CVEs found in an image", value=data_results["Grype_results"]["min_cves"])
            col5.metric(label ="Max number of CVEs found in an image", value=data_results["Grype_results"]["max_cves"])
            # -----------------------------------------

        with st.expander("JFrog detailed analysis results"):
            #-------- CVEs Distribution -----
            col1, col2, col3 = st.columns(3)
            col1.metric(label ="Average number of CVEs per image", value=round(data_results["JFrog_results"]["average_cves"], 2))
            col2.metric(label ="Median number of CVEs per image", value=data_results["JFrog_results"]["median_cves"])
            col3.metric(label ="Variance in the number of CVEs per image", value=round(data_results["JFrog_results"]["variance_cves"], 2))
                
            col4, col5 = st.columns(2)
            col4.metric(label ="Min number of CVEs found in an image", value=data_results["JFrog_results"]["min_cves"])
            col5.metric(label ="Max number of CVEs found in an image", value=data_results["JFrog_results"]["max_cves"])
            # -----------------------------------------
        
        with st.expander("DockerScout detailed analysis results"):
            #-------- CVEs Distribution -----
            col1, col2, col3 = st.columns(3)
            col1.metric(label ="Average number of CVEs per image", value=round(data_results["DockerScout_results"]["average_cves"], 2))
            col2.metric(label ="Median number of CVEs per image", value=data_results["DockerScout_results"]["median_cves"])
            col3.metric(label ="Variance in the number of CVEs per image", value=round(data_results["DockerScout_results"]["variance_cves"], 2))
                
            col4, col5 = st.columns(2)
            col4.metric(label ="Min number of CVEs found in an image", value=data_results["DockerScout_results"]["min_cves"])
            col5.metric(label ="Max number of CVEs found in an image", value=data_results["DockerScout_results"]["max_cves"])
            # -----------------------------------------
            
