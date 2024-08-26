import streamlit as st
import pandas as pd
import altair as alt
import plotly.express as px
import json
import numpy as np
from utils import get_distribution_cves_per_scanner, parse_unique_cves_field_original, solve_diff_sevs

# Page config
counter_all_pkgs = {}
type_dict = {}

st.set_page_config(
    page_title="Docker Image Vulnerability Analysis Dashboard",
    page_icon="🏂",
    layout="wide",
    initial_sidebar_state="expanded")

alt.themes.enable("dark")

# Load data

df_reshaped = pd.DataFrame()
# Create dropdown widgets on a sidebar for users  to select data
with st.sidebar:
    st.title('🏂 Docker Image Vulnerability Analysis Dashboard')
    
    # Select a category 
    image_name_list_n = ["Verified Images", "Sponsored Images", "Official Images"]
    selected_name_c = st.selectbox('Select a category of Docker images', image_name_list_n, index=len(image_name_list_n)-1)

    if selected_name_c == "Sponsored Images":
        df_reshaped = pd.read_csv('files/imagesSponsored.csv')
    elif selected_name_c == "Official Images":
        df_reshaped = pd.read_csv('files/imagesOfficial.csv')
    elif selected_name_c == "Verified Images":
        df_reshaped = pd.read_csv('files/imagesVerified.csv')
        
    # Select a image name
    image_name_list = list(df_reshaped.Name.unique())
    selected_name = st.selectbox('Select an image name', image_name_list, index=len(image_name_list)-1)
    df_selected_name = df_reshaped[df_reshaped.Name == selected_name]
    
    # Select a tag
    image_tag_list = list(df_selected_name.TagName)
    selected_tag = st.selectbox('Select a tag for the selected image name', image_tag_list, index=len(image_tag_list)-1)
    df_selected_tag = df_selected_name[df_selected_name.TagName == selected_tag]
    
    file_name = ""
    if selected_name_c == "Sponsored Images":
        df_selected_tag = df_selected_tag[(df_selected_tag['TagName'] == selected_tag) & (df_selected_tag['Name'] == selected_name)]
        file_name = "out-analysis/sponsored/" + df_selected_tag['Repository'].iloc[0] + "=" + selected_name  +  ":" + selected_tag + "_analysis.json"
    elif selected_name_c == "Official Images":
        file_name = "out-analysis/official/" + selected_name  +  ":" + selected_tag + "_analysis.json"
    elif selected_name_c == "Verified Images":
        df_selected_tag = df_selected_tag[(df_selected_tag['TagName'] == selected_tag) & (df_selected_tag['Name'] == selected_name)]
        file_name = "out-analysis/verified/" + df_selected_tag['Repository'].iloc[0] + "=" + selected_name  +  ":" + selected_tag + "_analysis.json"
        
    with open(file_name) as file:
        dataJSON = json.load(file)
    
    # Create a DataFrame from the JSON data    
    df_cves_detected_all_scanners = pd.json_normalize(dataJSON, 'cves_detected_all_scanners')
    df_unique_cves = pd.json_normalize(dataJSON, 'unique_cves')

tab1, tab2 = st.tabs(["Image Information and Metadata", "Vulnerability Analysis"])

with tab1:
    st.header("Image Information and Metadata")
    
    st.subheader('Image Category', divider='rainbow')
    st.write(df_selected_tag['Category'].iloc[0])
    st.subheader('Image Repository Name', divider='rainbow')
    st.write(df_selected_tag['Repository'].iloc[0])
    st.subheader('Image Name', divider='rainbow')
    st.write(selected_name)
    st.subheader('Image Tag (version)', divider='rainbow')
    st.write(selected_tag)    
    st.subheader('Tag Last Pushed', divider='rainbow')
    st.markdown("*This is the value of when the tag was last pushed at the time the data was downloded*")
    st.write(df_selected_tag['TagLastPushed'].iloc[0])
    st.subheader('Tag Digest', divider='rainbow')
    st.write(df_selected_tag['TagDigest'].iloc[0])
    st.subheader('Image Star Count (all tags)', divider='rainbow')
    st.write(df_selected_tag['StarCount'].iloc[0])
    st.subheader('Image Pull Count (all tags)', divider='rainbow')
    st.write(df_selected_tag['PullCount'].iloc[0])
    st.subheader('Image Subcategories', divider='rainbow')
    st.write(df_selected_tag['SubCategories'].iloc[0])

    # Display the filtered dataframe for debugging
    #st.write("DataFrame CVES_detected_all_scanners:")
    #st.dataframe(df_cves_detected_all_scanners)

    #if len(df_unique_cves) > 0:
        #st.write("DataFrame unique_cves:")
        #st.write(df_unique_cves)

with tab2:
    st.header("Vulnerability Analysis")
    
    st.subheader("Unique Vulnerabilities", divider='rainbow')
    st.markdown("*This corresponds to the union of all vulnerabilities found by all scanners*")
    
    num_unique_cves = len(df_unique_cves)
    
    col1, col2, col3 = st.columns(3)
    col1.metric(label="Unique Vulnerabilities found by All Scanners", value=num_unique_cves)
        
    
    tab2_1, tab2_2, tab2_3 = st.tabs(["Overall Vulnerability Landscape", "Detailed Unique Vulnerabilities", "Scanner Performance Analysis"])
    
    num_low_vulns = 0
    num_medium_vulns = 0
    num_high_vulns = 0
    num_critical_vulns = 0
    num_unassigned_vulns = 0
    num_diff_vulns = 0
    
    num_vulns_no_cvss = 0
    num_vulns_cvss = 0
    num_vulns_diff_cvss =0
    agreed_cvss_scores = []
        
    with tab2_2:
        st.subheader("Detailed Unique Vulnerabilities", divider='rainbow')   

        if num_unique_cves > 0:
            st.write("The unique vulnerabilities found (sorted by detection rate from higher to lower) are the following:")
    
            df_unique_cves_sorted = df_unique_cves.sort_values(by='detection_rate', ascending=False)
        
            

            for index, row in df_unique_cves_sorted.iterrows():
                detection_rate = (row['detection_rate']  / 5 )* 100
                columns_to_display = ['scanner_name','package', 'cvssv3_score', 'severity', 'type', 'is_fixed', 'fixed_version']
            
                i = row['scanner_cve_info']
                i_df = parse_unique_cves_field_original(i)
                cve_id = i_df['cve_id'].iloc[0]
                st.markdown("**:red["+cve_id+"]**")
                    
                with st.expander("See detailed analysis"):
                    st.write(i_df[columns_to_display])
                    
                    st.markdown("**Detected by the following Scanners:**")
                    detected_scanners = list(i_df.scanner_name.unique())
                    detected_scanners =  ', '.join(detected_scanners)
                    st.markdown("    :green["+detected_scanners+"]")
                    detection_rate = str(detection_rate) + "%"
                    st.metric(label="Detection rate for this vulnerability", value=detection_rate)
                
                
                    diff_severities = []
                    diff_cvss_scores = []
                    diff_types_set = set()
                    pkg_list = set()


                    for ind, r in i_df.iterrows():
                        packages = r['package']
                        type = r['type']
                        pkgs = packages.split(',')
                        scanner = r['scanner_name']
                        
                        
                        for pkg in pkgs:
                            pkg = pkg.strip()
                            if scanner == "Trivy":
                                final_pkg = pkg.split(' ')[1]
                            elif scanner == "Grype":
                                final_pkg = pkg
                            #elif scanner == "DockerScout":
                            elif  scanner == "JFrog":
                                final_pkg = pkg.split(':')
                                if len(final_pkg) > 1:
                                    final_pkg = final_pkg[1]
                                else:
                                    final_pkg = final_pkg[0]
                                    
                                pos = final_pkg.rfind('_')
                                if pos != -1:
                                    final_pkg = final_pkg[:pos] + '@' + final_pkg[pos + len('_'):]

                            elif scanner == "Snyk":
                                 final_pkg = pkg.split('/')
                                 final_pkg = final_pkg[len(final_pkg)-1]
                            elif  scanner == "DockerScout":
                                final_pkg = pkg
                            pkg_list.add(final_pkg)
                            
                        current_sev = r['severity'].upper().strip()
                        current_score = r['cvssv3_score'].upper().strip()
                        
                        if current_sev == "" or current_sev == "UNKNOWN" or current_sev == "UNSPECIFIED":
                            current_sev = "UNASSIGNED"
                        diff_severities.append(current_sev)
            
                        if current_score != "":
                            current_score = float(current_score)
                            if current_score != 0.0 :
                                diff_cvss_scores.append(current_score)
                               
                        list_langs = ["go-module", "python", "npm", "rust-crate", 
                                      "gem", "java-archive", "dotnet", "php-pecl", 
                                      "php-composer"]
                        list_os = ["deb", "apk", "rpm", "linux-kernel"] 
                        
                        if type != "":
                            if type in list_os:
                                type = "OsPackageVulnerability"
                            if type in list_langs:
                                type = "LanguageSpecificPackageVulnerability"
                            
                            diff_types_set.add(type)
                    
                    
                    pkg_list = list(pkg_list)
                    final_pkg_list = set()
                    for i in range(len(pkg_list)):
                        check = False
                        for j in range(0, len(pkg_list)):
                            if j == i:
                                continue
                            if pkg_list[i] in pkg_list[j]:
                                check = True
                        if check == False:
                            final_pkg_list.add(pkg_list[i])

                    st.write("Packages detected: ")
                    st.write(final_pkg_list)
                    
                    for item in final_pkg_list:
                        if item in counter_all_pkgs:
                            counter_all_pkgs[item] = counter_all_pkgs[item] + 1
                        else:
                            counter_all_pkgs[item] = 1
                    
                    diff_severities = set(diff_severities)
                    diff_cvss_scores = set(diff_cvss_scores)
                    
                    if len(diff_severities) > 1:
                        diff_severities = solve_diff_sevs(diff_severities)
            
                    if len(diff_severities) == 0:
                        st.metric(label="Severity of this vulnerability", value="UNASSIGNED")
                        num_unassigned_vulns += 1
                    elif len(diff_severities) >  1:
                        diff_severities = ', '.join(diff_severities)
                        st.markdown("   :red[Different severities were assigned by different scanners for this vulnerability:]")
                        st.write("      "+diff_severities)
                        num_diff_vulns += 1
                    else:
                        st.metric(label="Severity of this vulnerability", value=list(diff_severities)[0])
                        val =  list(diff_severities)[0]
                        if val == "MEDIUM":
                            num_medium_vulns += 1
                        elif val == "HIGH":
                            num_high_vulns += 1
                        elif val == "LOW":
                            num_low_vulns += 1
                        elif val == "CRITICAL":
                            num_critical_vulns += 1
                
                    if len(diff_cvss_scores) == 0:
                        st.metric(label="CVSS V3 Score for this vulnerability", value="UNASSIGNED")
                        num_vulns_no_cvss += 1
                    elif len(diff_cvss_scores) >  1:
                        diff_cvss_scores = ', '.join([str(num) for num in diff_cvss_scores])
                        st.markdown("   :red[Different CVSS V3 scores were assigned by different scanners for this vulnerability:]")
                        st.write("      "+diff_cvss_scores)
                        num_vulns_diff_cvss += 1
                    else:
                        num_vulns_cvss += 1
                        agreed_cvss_scores.append(list(diff_cvss_scores)[0])
                        st.metric(label="CVSS V3 Score for this vulnerability", value=list(diff_cvss_scores)[0])

                    if len(diff_types_set) == 0:
                        st.metric(label="Type of this vulnerability", value="UNASSIGNED")
                        if "UNASSIGNED" in type_dict:
                            type_dict["UNASSIGNED"] = type_dict["UNASSIGNED"] + 1
                        else:
                            type_dict["UNASSIGNED"] = 1
                    elif len(diff_types_set) == 1:
                        c = list(diff_types_set)[0]
                        st.metric(label="Type of this vulnerability", value=c)
                        if c in type_dict:
                            type_dict[c] = type_dict[c] + 1
                        else:
                            type_dict[c] = 1
                    elif len(diff_types_set) > 1:
                        types_sorted = sorted(list(diff_types_set))
                        types_all = ",".join(types_sorted)
                        st.metric(label="Type of this vulnerability", value=types_all)
                        if types_all in type_dict:
                            type_dict[types_all] = type_dict[types_all] + 1
                        else:
                            type_dict[types_all] = 1
                        
                

    with tab2_1:
        st.subheader("Overall Vulnerability Landscape", divider='rainbow')   
        
        st.write("Distribution of Vulnerabilities by Severity Across ALL Scanners")
        col1, col2, col3 = st.columns(3)
                 
        col1.metric(label ="Number of CRITICAL vulnerabilities", value=num_critical_vulns)
        col2.metric(label ="Number of HIGH vulnerabilities", value=num_high_vulns)
        col3.metric(label ="Number of MEDIUM vulnerabilities", value=num_medium_vulns)
        
        col4, col5, col6 = st.columns(3)
        col4.metric(label ="Number of LOW vulnerabilities", value=num_low_vulns)
        col5.metric(label ="Number of UNASSIGNED vulnerabilities", value=num_unassigned_vulns)
        col6.metric(label ="Number of vulnerabilities with different severity levels reported", value=num_diff_vulns)
        
        st.write("CVSS V3 Scores Analysis Across ALL Scanners")
        col7, col8, col9 = st.columns(3)
        col7.metric(label ="Number of vulnerabilities with no assigned CVSS V3 Score", value=num_vulns_no_cvss)
        col8.metric(label ="Number of vulnerabilities with an assigned CVSS V3 Score", value=num_vulns_cvss)
        col9.metric(label ="Number of vulnerabilities with different CVSS V3 Scores assigned", value=num_vulns_diff_cvss)
        
        agreed_cvss_scores_arr = np.array(agreed_cvss_scores)
        average_cvss_score = round(np.mean(agreed_cvss_scores_arr).item(), 2)
        
        st.metric(label="Average CVSS V3 Score across vulnerabilities with an assigned CVSS V3 Score", value=average_cvss_score)
        
        
        #----CHART DIST SEV
        l_S, m_S, h_S, c_S, u_S = get_distribution_cves_per_scanner(df_cves_detected_all_scanners, "Snyk", False)
        l_T, m_T, h_T, c_T, u_T = get_distribution_cves_per_scanner(df_cves_detected_all_scanners, "Trivy", False)
        l_G, m_G, h_G, c_G, u_G = get_distribution_cves_per_scanner(df_cves_detected_all_scanners, "Grype", False)
        l_D, m_D, h_D, c_D, u_D = get_distribution_cves_per_scanner(df_cves_detected_all_scanners, "DockerScout", False)
        l_J, m_J, h_J, c_J, u_J = get_distribution_cves_per_scanner(df_cves_detected_all_scanners, "JFrog", False)

        
        sev_per_scanner = {
            "Snyk_results": {
                "low_vulns": l_S, 
                "medium_vulns": m_S,  
                "high_vulns": h_S,
                "critical_vulns": c_S,
                "unassigned_vulns": u_S,  
            },
            "Trivy_results": {
                "low_vulns": l_T, 
                "medium_vulns": m_T,  
                "high_vulns": h_T,
                "critical_vulns": c_T,
                "unassigned_vulns": u_T,  
            },
            "Grype_results": {
                "low_vulns": l_G, 
                "medium_vulns": m_G,  
                "high_vulns": h_G,
                "critical_vulns": c_G,
                "unassigned_vulns": u_G,  
            },
            "DockerScout_results": {
                "low_vulns": l_D, 
                "medium_vulns": m_D,  
                "high_vulns": h_D,
                "critical_vulns": c_D,
                "unassigned_vulns": u_D,  
            },
            "JFrog_results": {
                "low_vulns": l_J, 
                "medium_vulns": m_J,  
                "high_vulns": h_J,
                "critical_vulns": c_J,
                "unassigned_vulns": u_J,  
            }
        }
        scanners = ["Snyk", "Trivy", "Grype", "DockerScout", "JFrog"]
        
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
        #---------TYPES DIST-----
    
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
            print("key: ", k)
            print("val: ", v)
        #-----------------
        
        #if len(df_unique_cves) > 0 :
           # st.write("Below is the histogram that shows the dection rate counts of CVEs. This essentially means: X vulnerabilites were found by Y scanners.")
            #counts = df_unique_cves.groupby('detection_rate')['cve_id'].count().reset_index()
            #counts.columns = ['detection_rate', 'Count']
            #hist_dist_cves = px.bar(counts, x='detection_rate', y='Count', title='Count of CVEs and detection rates')
            #st.plotly_chart(hist_dist_cves, use_container_width=True)
            
            
        st.write("Below is the table that shows how many vulnerabilities affected each listed package, after unifying results from all scanners.")
        df_pkgs = pd.DataFrame(list(counter_all_pkgs.items()), columns=['Package', 'CVEs affected'])
        df_pkgs_sorted = df_pkgs.sort_values(by='CVEs affected', ascending=False)
        st.table(df_pkgs_sorted)
        
        
    with tab2_3:
        st.subheader("Scanner Performance Analysis", divider='rainbow')   
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric(label=df_cves_detected_all_scanners['scanner_name'].iloc[0] +" detected CVEs", value=df_cves_detected_all_scanners['num_cves'].iloc[0])
        col2.metric(label=df_cves_detected_all_scanners['scanner_name'].iloc[1] +" detected CVEs", value=df_cves_detected_all_scanners['num_cves'].iloc[1])
        col3.metric(label=df_cves_detected_all_scanners['scanner_name'].iloc[2] +" detected CVEs", value=df_cves_detected_all_scanners['num_cves'].iloc[2])
        col4.metric(label=df_cves_detected_all_scanners['scanner_name'].iloc[3] +" detected CVEs", value=df_cves_detected_all_scanners['num_cves'].iloc[3])
        col5.metric(label=df_cves_detected_all_scanners['scanner_name'].iloc[4] +" detected CVEs", value=df_cves_detected_all_scanners['num_cves'].iloc[4])
        
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric(label=df_cves_detected_all_scanners['scanner_name'].iloc[0] +" comparative efficacy", value=round(df_cves_detected_all_scanners['relative_efficiency'].iloc[0],2))
        col2.metric(label=df_cves_detected_all_scanners['scanner_name'].iloc[1] +" comparative efficacy", value=round(df_cves_detected_all_scanners['relative_efficiency'].iloc[1], 2))
        col3.metric(label=df_cves_detected_all_scanners['scanner_name'].iloc[2] +" comparative efficacy", value=round(df_cves_detected_all_scanners['relative_efficiency'].iloc[2], 2))
        col4.metric(label=df_cves_detected_all_scanners['scanner_name'].iloc[3] +" comparative efficacy", value=round(df_cves_detected_all_scanners['relative_efficiency'].iloc[3],2))
        col5.metric(label=df_cves_detected_all_scanners['scanner_name'].iloc[4] +" comparative efficacy", value=round(df_cves_detected_all_scanners['relative_efficiency'].iloc[4],2))

        scanner_name_list = list(df_cves_detected_all_scanners.scanner_name.unique())
        selected_scanner_name = st.selectbox('Select a scanner', scanner_name_list, index=len(scanner_name_list)-1)
        
        get_distribution_cves_per_scanner(df_cves_detected_all_scanners, selected_scanner_name, True)
        
        