import streamlit as st
import pandas as pd
import altair as alt
import plotly.express as px
import numpy as np
import json
import glob
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
import itertools
from utils import process_file, parse_unique_cves_field_original, extract_severity, extract_packages, extract_fix_status, compute_severities_by_scanner_mod, packages_by_scanner_mod, fix_statuses_by_scanner_mod, combine_dicts, process_image, get_metadata, compute_stats, solve_diff_sevs, extract_types

# Paths
DIR_OFFICIAL = 'out-analysis/official/'
DIR_VERIFIED = 'out-analysis/verified/'
DIR_SPONSORED = 'out-analysis/sponsored/'

df_official = pd.read_csv('files/imagesOfficial.csv')
df_verified = pd.read_csv('files/imagesVerified.csv')
df_sponsored = pd.read_csv('files/imagesSponsored.csv')

class ScannerResults:
    def __init__(self, scanner_name, relative_efficacies_list, num_cves, num_cves_list, 
                 low_vulns, medium_vulns, high_vulns, critical_vulns, un_vulns, 
                 pkgs_affected_dict, fixed_vulns, not_fixed_vulns,
                 vulns_cvss, vulns_no_cvss, avg_cvss):
        self.scanner_name = scanner_name
        self.relative_efficacies_list = relative_efficacies_list
        self.num_cves = num_cves
        self.num_cves_list = num_cves_list
        self.low_vulns = low_vulns
        self.medium_vulns = medium_vulns
        self.high_vulns = high_vulns
        self.critical_vulns = critical_vulns
        self.unassigned_vulns = un_vulns  
        self.pkgs_affected_dict = pkgs_affected_dict
        self.fixed_vulns = fixed_vulns
        self.not_fixed_vulns = not_fixed_vulns
        self.vulns_cvss = vulns_cvss
        self.vulns_no_cvss = vulns_no_cvss
        self.avg_cvss = avg_cvss

# Page config
counter_all_pkgs = {}

st.set_page_config(
    page_title="Docker Image Vulnerability Analysis Dashboard",
    page_icon="🏂",
    layout="wide",
    initial_sidebar_state="expanded")

alt.themes.enable("dark")

df_reshaped = pd.DataFrame()
# Create dropdown widgets on a sidebar for users  to select data
with st.sidebar:
    st.title('🏂 Docker Image Vulnerability Analysis Dashboard')
    
    # Select a category 
    image_name_list_n = ["Verified Images", "Sponsored Images", "Official Images"]
    selected_name_c = st.selectbox('Select a category of Docker images', image_name_list_n, index=len(image_name_list_n)-1)

    if selected_name_c == "Sponsored Images":
        df_reshaped = df_sponsored
    elif selected_name_c == "Official Images":
        df_reshaped = df_official
    elif selected_name_c == "Verified Images":
        df_reshaped =  df_verified
        
    # Select a image name
    image_name_list = list(df_reshaped.Name.unique())
    selected_img_name = st.selectbox('Select an image name', image_name_list, index=len(image_name_list)-1)
    df_selected_name = df_reshaped[df_reshaped.Name == selected_img_name]

# ----------------- Open necessary files and information
num_images_analysed = 0
pattern_files = ""

directory = ''
if selected_name_c == "Official Images":
    directory = DIR_OFFICIAL
    pattern_files = selected_img_name + ":*_analysis.json"
elif selected_name_c == "Verified Images":
    directory = DIR_VERIFIED
    repo = df_selected_name['Repository'].iloc[0]
    pattern_files = repo + "=" + selected_img_name + ":*_analysis.json"
elif selected_name_c == "Sponsored Images":
    repo = df_selected_name['Repository'].iloc[0]
    pattern_files = repo + "=" + selected_img_name + ":*_analysis.json"
    directory = DIR_SPONSORED

df_cves_detected_all_scanners = pd.DataFrame()
df_unique_cves = pd.DataFrame()

df_images_stats = pd.DataFrame(columns=[
    'Image and Tag Name', 'Number of unique CVEs', 
    'Low CVEs', 'Medium CVEs', 'High CVEs', 'Critical CVEs', 
    'Unassigned CVEs', 'Differing CVEs', 'Number of Pulls',
    'Number of Repo Stars', 'Category', 'SubCategories', 'Size'])

num_cves_list = []

# Load dataframes
  
pattern = os.path.join(directory, pattern_files)
num_images_analysed = 0
file_list = [filename for filename in glob.glob(pattern) if os.path.isfile(filename)]

with ProcessPoolExecutor() as executor:
    results = list(executor.map(process_file, file_list))
    
# Combine results
for df1, df2, num, img_name in results:
    num_cves_list.append(num)
    df_cves_detected_all_scanners = pd.concat([df_cves_detected_all_scanners, df1], ignore_index=True)
    df_unique_cves = pd.concat([df_unique_cves, df2], ignore_index=True)
    num_images_analysed += 1
    
    num_unique_cves, final_pkg_list, num_low_vulns, num_medium_vulns, num_high_vulns, num_critical_vulns, num_unassigned_vulns, num_diff_vulns = process_image(df2)
    c, sta, p, sub, siz = get_metadata(img_name, selected_name_c, df_official, df_verified, df_sponsored)
    # TODO: add here the cvss avg and so??
    single_row = pd.DataFrame([{
        'Image and Tag Name': img_name, 
        'Number of unique CVEs': num_unique_cves, 
        'Low CVEs': num_low_vulns,
        'Medium CVEs': num_medium_vulns,
        'High CVEs': num_high_vulns,
        'Critical CVEs': num_critical_vulns,
        'Unassigned CVEs': num_unassigned_vulns,
        'Differing CVEs': num_diff_vulns,
        'Number of Pulls': p, 
        'Number of Repo Stars': sta,
        'Category': c,
        'SubCategories': sub,
        'Size': siz,
    }])
    df_images_stats = pd.concat([df_images_stats, single_row], ignore_index=True)

# Convert to numpy array
data_array = np.array(num_cves_list)

# Compute statistics
average_cves_per_image = np.mean(data_array).item()
median_cves_per_image = np.median(data_array).item()
variance_cves_per_image = np.var(data_array, ddof=1).item()  # ddof=1 for sample variance
std_dev_cves_per_image = np.std(data_array, ddof=1).item()  # ddof=1 for sample standard deviation
min_value_cves_per_images = np.min(data_array).item()
max_value_cves_per_image = np.max(data_array).item()
range_value_cves_per_image = max_value_cves_per_image - min_value_cves_per_images

data_stats = {
    "number_images_analysed": num_images_analysed,
    "len_num_cves_list": len(num_cves_list),
    "average_cves_per_image": average_cves_per_image,
    "median_cves_per_image": median_cves_per_image,
    "variance_cves_per_image": variance_cves_per_image,
    "std_dev_cves_per_image": std_dev_cves_per_image,
    "min_value_cves_per_images": min_value_cves_per_images,
    "max_value_cves_per_image": max_value_cves_per_image,
    "range_value_cves_per_image": range_value_cves_per_image,
}

# Compute the unique CVEs among all images     
unique_CVEs_all = {}
        
for index, row in df_unique_cves.iterrows():
    scanner_cve_inf = row['scanner_cve_info']
    detection_rate = row['detection_rate']
    scanner_cve_inf_df = parse_unique_cves_field_original(scanner_cve_inf)
    cve_id = scanner_cve_inf_df['cve_id'].iloc[0]
    
    if cve_id in unique_CVEs_all:
        unique_CVEs_all[cve_id].append(scanner_cve_inf_df)
    else:
        unique_CVEs_all[cve_id] = [scanner_cve_inf_df]
            
# Create DF to store the number of images in which each CVE is present
cves_freq_df = pd.DataFrame(columns=[
    'CVE ID', 'Images Present Count', 
    'Image Present %', 'Average Detection Rate', 
    'Packages Affected', 'Fix Status'])

num_low_vulns = 0
num_medium_vulns = 0
num_high_vulns = 0
num_critical_vulns = 0
num_unassigned_vulns = 0
num_diff_vulns = 0
num_reports_unmatch = 0

num_vulns_differ_fix_status = 0
num_vulns_fixed = 0
num_vulns_not_fixed = 0

num_vulns_no_cvss = 0
num_vulns_cvss = 0
num_vulns_diff_cvss = 0
agreed_cvss_scores = []

unique_pkgs_affected = {}
type_dict = {}

for key, value in unique_CVEs_all.items():
    
    value_sev_set = set()
    scores_set = set()
    equal_status_set = set()
    types_set = set()
    detection_rates_list = []
    pkgs_set = set() # this is the list of affected packages for a unique CVE ID.
        
    for scanner_cve_info_obj_df in value:
        detection_rates_list.append(len(scanner_cve_info_obj_df))
        value_sev, score_cvss = extract_severity(key, scanner_cve_info_obj_df, False)

        pkgs = extract_packages(scanner_cve_info_obj_df)
        fixed_status = extract_fix_status(scanner_cve_info_obj_df)
        type_val = extract_types(scanner_cve_info_obj_df)
        types_set.update(type_val)
        equal_status_set.add(fixed_status)
        pkgs_set.update(pkgs)
        value_sev_set.add(value_sev)
        if score_cvss != 0.0:
            scores_set.add(score_cvss)
     
    stat_fix = "not_fixed"                 
    if len(equal_status_set) == 1:
        if list(equal_status_set)[0] == "fixed":
            num_vulns_fixed += 1
            stat_fix = "fixed"
        elif list(equal_status_set)[0] == "different_statuses":
            num_vulns_differ_fix_status += 1
        elif list(equal_status_set)[0] == "not_fixed":
            num_vulns_not_fixed += 1
            stat_fix = "not_fixed"
    elif len(equal_status_set) > 1:
        num_vulns_differ_fix_status += 1
        stat_fix = "different_statuses"
        
    if len(scores_set) == 0:
        num_vulns_no_cvss += 1
    elif len(scores_set) == 1:
        ss = list(scores_set)[0]
        if ss == -1.0:
            num_vulns_diff_cvss += 1
        else:
            num_vulns_cvss += 1
            agreed_cvss_scores.append(ss)
    elif len(scores_set) > 1:
        num_vulns_diff_cvss += 1
        
    if len(types_set) == 0:
        print("ERROR OCCURRED WHILE ASSESING types, NO VALUE ASSIGNED")
    elif len(types_set) == 1:
        typ_v = list(types_set)[0]
        if typ_v in type_dict:
            type_dict[typ_v] += 1
        else:
            type_dict[typ_v] = 1
    elif len(types_set) > 1:
        types_sorted = sorted(list(types_set))
        typ_v = ",".join(types_sorted)
        if typ_v in type_dict:
            type_dict[typ_v] += 1
        else:
            type_dict[typ_v] = 1
        
    if len(value_sev_set) > 1:
        value_sev_set = solve_diff_sevs(value_sev_set)
        
    if len(value_sev_set) == 0:
        print("ERROR OCCURRED WHILE ASSESING SEVERITIES, NO VALUE ASSIGNED")
    elif len(value_sev_set) == 1:
        val = list(value_sev_set)[0]
        if val == "LOW":
            num_low_vulns += 1
        elif val == "MEDIUM":
            num_medium_vulns += 1
        elif val == "HIGH":
            num_high_vulns += 1
        elif val == "CRITICAL":
            num_critical_vulns += 1
        elif val == "UNASSIGNED":
            num_unassigned_vulns += 1
        elif val == "DIFFERING":
            num_diff_vulns += 1
        else:
            print("UNKNOWN SEV VALUE")
            print(val)
    else:
        #num_reports_unmatch += 1
        num_diff_vulns += 1
              
    # compute avg detection rates 
    detection_rates_array = np.array(detection_rates_list)
    avg_detection_rate = np.mean(detection_rates_array).item()

    perc = (len(value) / num_images_analysed)*100
    single_row = pd.DataFrame([{
        'CVE ID': key, 
        'Images Present Count': len(value), 
        'Image Present %': perc,
        'Average Detection Rate': avg_detection_rate,
        'Packages Affected': list(pkgs_set),
        'Fix Status': stat_fix,
        # TODO: add to this the CVSS score of the CVE and its severity
    }])
    cves_freq_df = pd.concat([cves_freq_df, single_row], ignore_index=True)
    
    for item in list(pkgs_set):
        if item in unique_pkgs_affected:
            unique_pkgs_affected[item] = unique_pkgs_affected[item] + 1
        else:
            unique_pkgs_affected[item] = 1
            
snyk_obj = ScannerResults(
    scanner_name="Snyk",
    relative_efficacies_list=[],
    num_cves=0,
    num_cves_list=[],
    low_vulns=0,
    medium_vulns=0,
    high_vulns=0,
    critical_vulns=0,
    un_vulns=0,
    pkgs_affected_dict={},
    fixed_vulns=0,
    not_fixed_vulns=0,
    vulns_cvss=0,
    vulns_no_cvss=0,
    avg_cvss=0.0
)

trivy_obj = ScannerResults(
    scanner_name="Trivy",
    relative_efficacies_list=[],
    num_cves=0,
    num_cves_list=[],
    low_vulns=0,
    medium_vulns=0,
    high_vulns=0,
    critical_vulns=0,
    un_vulns=0,
    pkgs_affected_dict={},
    fixed_vulns=0,
    not_fixed_vulns=0,
    vulns_cvss=0,
    vulns_no_cvss=0,
    avg_cvss=0.0
)

grype_obj = ScannerResults(
    scanner_name="Grype",
    relative_efficacies_list=[],
    num_cves=0,
    num_cves_list=[],
    low_vulns=0,
    medium_vulns=0,
    high_vulns=0,
    critical_vulns=0,
    un_vulns=0,
    pkgs_affected_dict={},
    fixed_vulns=0,
    not_fixed_vulns=0,
    vulns_cvss=0,
    vulns_no_cvss=0,
    avg_cvss=0.0
)

jfrog_obj = ScannerResults(
    scanner_name="JFrog",
    relative_efficacies_list=[],
    num_cves=0,
    num_cves_list=[],
    low_vulns=0,
    medium_vulns=0,
    high_vulns=0,
    critical_vulns=0,
    un_vulns=0,
    pkgs_affected_dict={},
    fixed_vulns=0,
    not_fixed_vulns=0,
    vulns_cvss=0,
    vulns_no_cvss=0,
    avg_cvss=0.0
)

dockerscout_obj = ScannerResults(
    scanner_name="DockerScout",
    relative_efficacies_list=[],
    num_cves=0,
    num_cves_list=[],
    low_vulns=0,
    medium_vulns=0,
    high_vulns=0,
    critical_vulns=0,
    un_vulns=0,
    pkgs_affected_dict={},
    fixed_vulns=0,
    not_fixed_vulns=0,
    vulns_cvss=0,
    vulns_no_cvss=0,
    avg_cvss=0.0
)

for index, row in df_cves_detected_all_scanners.iterrows():
    relative_efficacy = row['relative_efficiency']
    scanner_name = row['scanner_name']
    num_cves_detected = row['num_cves']
    cves_list = row['cves']
    
    l_vulns, m_vulns, h_vulns, c_vulns, u_vulns, cvss_y, no_cvss, avg_cvss = compute_severities_by_scanner_mod(cves_list)
    
    pkgs_dict_scanner = packages_by_scanner_mod(scanner_name, cves_list)
    fixed_yes, fixed_no = fix_statuses_by_scanner_mod(cves_list)
    
    if scanner_name == "Snyk":
        snyk_obj.relative_efficacies_list.append(relative_efficacy)
        snyk_obj.num_cves += num_cves_detected
        snyk_obj.num_cves_list.append(num_cves_detected)
        
        snyk_obj.low_vulns += l_vulns
        snyk_obj.medium_vulns += m_vulns
        snyk_obj.high_vulns += h_vulns
        snyk_obj.critical_vulns += c_vulns
        snyk_obj.unassigned_vulns += u_vulns
        
        combine_dicts(pkgs_dict_scanner, snyk_obj.pkgs_affected_dict)
        snyk_obj.fixed_vulns = fixed_yes
        snyk_obj.not_fixed_vulns = fixed_no
        
        snyk_obj.vulns_cvss = cvss_y
        snyk_obj.vulns_no_cvss = no_cvss
        snyk_obj.avg_cvss = avg_cvss
        
    elif scanner_name == "Trivy":
        trivy_obj.relative_efficacies_list.append(relative_efficacy)
        trivy_obj.num_cves += num_cves_detected
        trivy_obj.num_cves_list.append(num_cves_detected)
        
        trivy_obj.low_vulns += l_vulns
        trivy_obj.medium_vulns += m_vulns
        trivy_obj.high_vulns += h_vulns
        trivy_obj.critical_vulns += c_vulns
        trivy_obj.unassigned_vulns += u_vulns
        
        combine_dicts(pkgs_dict_scanner, trivy_obj.pkgs_affected_dict)
        trivy_obj.fixed_vulns = fixed_yes
        trivy_obj.not_fixed_vulns = fixed_no
        
        trivy_obj.vulns_cvss = cvss_y
        trivy_obj.vulns_no_cvss = no_cvss
        trivy_obj.avg_cvss = avg_cvss
        
    elif scanner_name == "Grype":
        grype_obj.relative_efficacies_list.append(relative_efficacy)
        grype_obj.num_cves += num_cves_detected
        grype_obj.num_cves_list.append(num_cves_detected)
        
        grype_obj.low_vulns += l_vulns
        grype_obj.medium_vulns += m_vulns
        grype_obj.high_vulns += h_vulns
        grype_obj.critical_vulns += c_vulns
        grype_obj.unassigned_vulns += u_vulns
        
        combine_dicts(pkgs_dict_scanner, grype_obj.pkgs_affected_dict)
        grype_obj.fixed_vulns = fixed_yes
        grype_obj.not_fixed_vulns = fixed_no
        
        grype_obj.vulns_cvss = cvss_y
        grype_obj.vulns_no_cvss = no_cvss
        grype_obj.avg_cvss = avg_cvss
        
    elif scanner_name == "DockerScout":
        dockerscout_obj.relative_efficacies_list.append(relative_efficacy)
        dockerscout_obj.num_cves += num_cves_detected
        dockerscout_obj.num_cves_list.append(num_cves_detected)
        
        dockerscout_obj.low_vulns += l_vulns
        dockerscout_obj.medium_vulns += m_vulns
        dockerscout_obj.high_vulns += h_vulns
        dockerscout_obj.critical_vulns += c_vulns
        dockerscout_obj.unassigned_vulns += u_vulns
        
        dockerscout_obj.vulns_cvss = cvss_y
        dockerscout_obj.vulns_no_cvss = no_cvss
        dockerscout_obj.avg_cvss = avg_cvss
        
        combine_dicts(pkgs_dict_scanner, dockerscout_obj.pkgs_affected_dict)
        dockerscout_obj.fixed_vulns = fixed_yes
        dockerscout_obj.not_fixed_vulns = fixed_no
        
    elif scanner_name == "JFrog":
        jfrog_obj.relative_efficacies_list.append(relative_efficacy)
        jfrog_obj.num_cves += num_cves_detected
        jfrog_obj.num_cves_list.append(num_cves_detected)
        
        jfrog_obj.low_vulns += l_vulns
        jfrog_obj.medium_vulns += m_vulns
        jfrog_obj.high_vulns += h_vulns
        jfrog_obj.critical_vulns += c_vulns
        jfrog_obj.unassigned_vulns += u_vulns
        
        combine_dicts(pkgs_dict_scanner, jfrog_obj.pkgs_affected_dict)
        jfrog_obj.fixed_vulns = fixed_yes
        jfrog_obj.not_fixed_vulns = fixed_no
        
        jfrog_obj.vulns_cvss = cvss_y
        jfrog_obj.vulns_no_cvss = no_cvss
        jfrog_obj.avg_cvss = avg_cvss

# Compute statistics
a_S_effic, m_S_effic, v_S_effic, std_S_effic, min_S_effic, max_S_effic, range_S_effic = compute_stats(snyk_obj.relative_efficacies_list)
a_T_effic, m_T_effic, v_T_effic, std_T_effic, min_T_effic, max_T_effic, range_T_effic = compute_stats(trivy_obj.relative_efficacies_list)
a_G_effic, m_G_effic, v_G_effic, std_G_effic, min_G_effic, max_G_effic, range_G_effic = compute_stats(grype_obj.relative_efficacies_list)
a_D_effic, m_D_effic, v_D_effic, std_D_effic, min_D_effic, max_D_effic, range_D_effic = compute_stats(dockerscout_obj.relative_efficacies_list)
a_J_effic, m_J_effic, v_J_effic, std_J_effic, min_J_effic, max_J_effic, range_J_effic = compute_stats(jfrog_obj.relative_efficacies_list)

a_S_cves, m_S_cves, v_S_cves, std_S_cves, min_S_cves, max_S_cves, range_S_cves = compute_stats(snyk_obj.num_cves_list)
a_T_cves, m_T_cves, v_T_cves, std_T_cves, min_T_cves, max_T_cves, range_T_cves = compute_stats(trivy_obj.num_cves_list)
a_G_cves, m_G_cves, v_G_cves, std_G_cves, min_G_cves, max_G_cves, range_G_cves = compute_stats(grype_obj.num_cves_list)
a_D_cves, m_D_cves, v_D_cves, std_D_cves, min_D_cves, max_D_cves, range_D_cves = compute_stats(dockerscout_obj.num_cves_list)
a_J_cves, m_J_cves, v_J_cves, std_J_cves, min_J_cves, max_J_cves, range_J_cves = compute_stats(jfrog_obj.num_cves_list)

agreed_cvss_scores_arr = np.array(agreed_cvss_scores)
average_cvss_score = round(np.mean(agreed_cvss_scores_arr).item(), 2)

data_results = {
    "number_images_analysed": num_images_analysed,
    "num_unique_vulnerabilities": len(unique_CVEs_all),
    "low_vulnerabilities": num_low_vulns,
    "medium_vulnerabilitites": num_medium_vulns,
    "high_vulnerabilities": num_high_vulns,
    "critical_vulnerabilitites": num_critical_vulns,
    "unassigned_vulnerabilities": num_unassigned_vulns,
    "differing_vulnerabilitites": num_diff_vulns,
    "reports_dont_match_vulns": num_reports_unmatch,
    "fixed_vulnerabilities": num_vulns_fixed,
    "not_fixed_vulnerabilities": num_vulns_not_fixed,
    "vulnerabilities_different_fix_status": num_vulns_differ_fix_status,
    "vulnerabilites_agreed_upon_cvss_score": num_vulns_cvss,
    "vulnerabilities_different_cvss_scores": num_vulns_diff_cvss,
    "vulnerabilities_no_cvss_score": num_vulns_no_cvss,
    "average_cvss_score_per_vuln": average_cvss_score,
    "Snyk_results": {
        "num_CVES_detected": snyk_obj.num_cves,
        "average_efficacy": a_S_effic,
        "median_efficacy":m_S_effic,
        "variance_efficacy":v_S_effic,
        "std_dev_efficacy":std_S_effic,
        "min_efficacy":min_S_effic, 
        "max_efficacy":max_S_effic,
        "range_efficacy":range_S_effic,
        "average_cves": a_S_cves,
        "median_cves": m_S_cves,
        "variance_cves": v_S_cves,
        "std_dev_cves": std_S_cves,
        "min_cves": min_S_cves,
        "max_cves": max_S_cves,
        "range_cves": range_S_cves,
        "low_vulns": snyk_obj.low_vulns,
        "medium_vulns": snyk_obj.medium_vulns,
        "high_vulns": snyk_obj.high_vulns,
        "critical_vulns": snyk_obj.critical_vulns,
        "unassigned_vulns": snyk_obj.unassigned_vulns,
        "fixed_vulns": snyk_obj.fixed_vulns,
        "not_fixed_vulns": snyk_obj.not_fixed_vulns,
        "pkgs_affected_dict": snyk_obj.pkgs_affected_dict,
        "cvss_vulns": snyk_obj.vulns_cvss,
        "no_cvss_vulns": snyk_obj.vulns_no_cvss,
        "avg_cvss": snyk_obj.avg_cvss
    },
    "Trivy_results": {
        "num_CVES_detected": trivy_obj.num_cves,
        "average_efficacy": a_T_effic,
        "median_efficacy":m_T_effic,
        "variance_efficacy":v_T_effic,
        "std_dev_efficacy":std_T_effic,
        "min_efficacy":min_T_effic, 
        "max_efficacy":max_T_effic,
        "range_efficacy":range_T_effic,
        "average_cves": a_T_cves,
        "median_cves": m_T_cves,
        "variance_cves": v_T_cves,
        "std_dev_cves": std_T_cves,
        "min_cves": min_T_cves,
        "max_cves": max_T_cves,
        "range_cves": range_T_cves,
        "low_vulns": trivy_obj.low_vulns,
        "medium_vulns": trivy_obj.medium_vulns,
        "high_vulns": trivy_obj.high_vulns,
        "critical_vulns": trivy_obj.critical_vulns,
        "unassigned_vulns": trivy_obj.unassigned_vulns,
        "fixed_vulns": trivy_obj.fixed_vulns,
        "not_fixed_vulns": trivy_obj.not_fixed_vulns,
        "pkgs_affected_dict": trivy_obj.pkgs_affected_dict,
        "cvss_vulns": trivy_obj.vulns_cvss,
        "no_cvss_vulns": trivy_obj.vulns_no_cvss,
        "avg_cvss": trivy_obj.avg_cvss
    },
    "Grype_results": {
        "num_CVES_detected": grype_obj.num_cves,
        "average_efficacy": a_G_effic,
        "median_efficacy":m_G_effic,
        "variance_efficacy":v_G_effic,
        "std_dev_efficacy":std_G_effic,
        "min_efficacy":min_G_effic, 
        "max_efficacy":max_G_effic,
        "range_efficacy":range_G_effic,
        "average_cves": a_G_cves,
        "median_cves": m_G_cves,
        "variance_cves": v_G_cves,
        "std_dev_cves": std_G_cves,
        "min_cves": min_G_cves,
        "max_cves": max_G_cves,
        "range_cves": range_G_cves,
         "low_vulns": grype_obj.low_vulns,
        "medium_vulns": grype_obj.medium_vulns,
        "high_vulns": grype_obj.high_vulns,
        "critical_vulns": grype_obj.critical_vulns,
        "unassigned_vulns": grype_obj.unassigned_vulns,
        "fixed_vulns": grype_obj.fixed_vulns,
        "not_fixed_vulns": grype_obj.not_fixed_vulns,
        "pkgs_affected_dict": grype_obj.pkgs_affected_dict,
        "cvss_vulns": grype_obj.vulns_cvss,
        "no_cvss_vulns": grype_obj.vulns_no_cvss,
        "avg_cvss": grype_obj.avg_cvss
    },
    "JFrog_results": {
        "num_CVES_detected": jfrog_obj.num_cves,
        "average_efficacy": a_J_effic,
        "median_efficacy":m_J_effic,
        "variance_efficacy":v_J_effic,
        "std_dev_efficacy":std_J_effic,
        "min_efficacy":min_J_effic, 
        "max_efficacy":max_J_effic,
        "range_efficacy":range_J_effic,
        "average_cves": a_J_cves,
        "median_cves": m_J_cves,
        "variance_cves": v_J_cves,
        "std_dev_cves": std_J_cves,
        "min_cves": min_J_cves,
        "max_cves": max_J_cves,
        "range_cves": range_J_cves,
         "low_vulns": jfrog_obj.low_vulns,
        "medium_vulns": jfrog_obj.medium_vulns,
        "high_vulns": jfrog_obj.high_vulns,
        "critical_vulns": jfrog_obj.critical_vulns,
        "unassigned_vulns": jfrog_obj.unassigned_vulns,
        "fixed_vulns": jfrog_obj.fixed_vulns,
        "not_fixed_vulns": jfrog_obj.not_fixed_vulns,
        "pkgs_affected_dict": jfrog_obj.pkgs_affected_dict,
        "cvss_vulns": jfrog_obj.vulns_cvss,
        "no_cvss_vulns": jfrog_obj.vulns_no_cvss,
        "avg_cvss": jfrog_obj.avg_cvss
    },
    "DockerScout_results": {
        "num_CVES_detected": dockerscout_obj.num_cves,
        "average_efficacy": a_D_effic,
        "median_efficacy":m_D_effic,
        "variance_efficacy":v_D_effic,
        "std_dev_efficacy":std_D_effic,
        "min_efficacy":min_D_effic, 
        "max_efficacy":max_D_effic,
        "range_efficacy":range_D_effic,
        "average_cves": a_D_cves,
        "median_cves": m_D_cves,
        "variance_cves": v_D_cves,
        "std_dev_cves": std_D_cves,
        "min_cves": min_D_cves,
        "max_cves": max_D_cves,
        "range_cves": range_D_cves,
         "low_vulns": dockerscout_obj.low_vulns,
        "medium_vulns": dockerscout_obj.medium_vulns,
        "high_vulns": dockerscout_obj.high_vulns,
        "critical_vulns": dockerscout_obj.critical_vulns,
        "unassigned_vulns": dockerscout_obj.unassigned_vulns,
        "fixed_vulns": dockerscout_obj.fixed_vulns,
        "not_fixed_vulns": dockerscout_obj.not_fixed_vulns,
        "pkgs_affected_dict": dockerscout_obj.pkgs_affected_dict,
        "cvss_vulns": dockerscout_obj.vulns_cvss,
        "no_cvss_vulns": dockerscout_obj.vulns_no_cvss,
        "avg_cvss": dockerscout_obj.avg_cvss
    }
}

data_cves_df = cves_freq_df.sort_values(by='Images Present Count', ascending=False)
pkgs_freq_df = pd.DataFrame(list(unique_pkgs_affected.items()), columns=['Package', 'Count'])

# -------------------------------------

tab1, tab2 = st.tabs(["Image Information and Metadata", "Vulnerability Analysis"])

with tab1:
    st.header("Image Information and Metadata")
    
    st.metric(label = "Number of Docker images analysed", value=data_stats["number_images_analysed"])
    
    st.subheader('Images Category', divider='rainbow')
    st.write(df_selected_name['Category'].iloc[0])
    st.subheader('Image Repository Name', divider='rainbow')
    st.write(df_selected_name['Repository'].iloc[0])
    st.subheader('Image Name', divider='rainbow')
    st.write(selected_img_name)
    st.subheader('Tags (versions) available for this image', divider='rainbow')
    for index, row in df_selected_name.iterrows(): 
        st.write(row['TagName'])
    st.subheader('Image Star Count (all tags)', divider='rainbow')
    st.write(df_selected_name['StarCount'].iloc[0])
    st.subheader('Image Pull Count (all tags)', divider='rainbow')
    st.write(df_selected_name['PullCount'].iloc[0])
    st.subheader('Image Subcategories', divider='rainbow')
    st.write(df_selected_name['SubCategories'].iloc[0])
    
    st.subheader('Images Detailed Information', divider='rainbow')
    st.dataframe(df_selected_name)
    
    st.subheader("Images Analysed Vulnerability Distribution and Metadata")
    st.dataframe(df_images_stats)
    
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
        st.markdown("Average :red[relative efficacy] by scanner")
        
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
            