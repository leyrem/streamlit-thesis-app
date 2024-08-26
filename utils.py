import streamlit as st
import pandas as pd
import requests
import json
import numpy as np

NVD_API_KEY = "3c7af097-4e2c-4468-ba62-7519d3372834"

def parse_unique_cves_field_original(scanner_cve_info):
# Initialize lists to store extracted data
    scanner_names = []
    cve_ids = []
    packages = []
    cvssv3_scores = []
    severities = []
    types = []
    is_fixeds = []
    fixed_versions = []
    # Extract data from each dictionary in 'scanner_cve_info'
    for item in scanner_cve_info:
        scanner_names.append(item['scanner_name'])
        cve_ids.append(item['cve_info']['cve_id'])
        # Convert list to comma-separated string
        packages.append(', '.join(item['cve_info']['package']))
        cvssv3_scores.append(item['cve_info']['cvssv3_score'])
        severities.append(item['cve_info']['severity'])
        types.append(item['cve_info']['type'])
        is_fixeds.append(item['cve_info']['is_fixed'])
        fixed_versions.append(item['cve_info']['fixed_version'])
    # Create DataFrame
    df = pd.DataFrame({
        'scanner_name': scanner_names,
        'cve_id': cve_ids,
        'package': packages,
        'cvssv3_score': cvssv3_scores,
        'severity': severities,
        'type': types,
        'is_fixed': is_fixeds,
        'fixed_version': fixed_versions
    })
    return df

def parse_unique_cves_field(scanner_cve_info):
    # Initialize lists to store extracted data
    scanner_names = []
    cve_ids = []
    packages = []
    cvssv3_scores = []
    severities = []
    types = []
    is_fixeds = []
    fixed_versions = []
    
    # Fix the JSON string by replacing single quotes with double quotes
    fixed_string = scanner_cve_info.replace("'", '"')
    fixed_string = fixed_string.replace("True", "true").replace("False", "false")
    scanner_cve_info_fix = json.loads(fixed_string)


    # Extract data from each dictionary in 'scanner_cve_info'
    for item in scanner_cve_info_fix:
        scanner_names.append(item['scanner_name'])
        cve_ids.append(item['cve_info']['cve_id'])
        # Convert list to comma-separated string
        packages.append(', '.join(item['cve_info']['package']))
        cvssv3_scores.append(item['cve_info']['cvssv3_score'])
        severities.append(item['cve_info']['severity'])
        types.append(item['cve_info']['type'])
        is_fixeds.append(item['cve_info']['is_fixed'])
        fixed_versions.append(item['cve_info']['fixed_version'])

    # Create DataFrame
    df = pd.DataFrame({
        'scanner_name': scanner_names,
        'cve_id': cve_ids,
        'package': packages,
        'cvssv3_score': cvssv3_scores,
        'severity': severities,
        'type': types,
        'is_fixed': is_fixeds,
        'fixed_version': fixed_versions
    })

    return df


def get_distribution_cves_per_scanner(df_cves_detected_all_scanners, selected_scanner_name, show):
    
    selected_rows = df_cves_detected_all_scanners[df_cves_detected_all_scanners['scanner_name'] == selected_scanner_name]
    
    num_low_vulns = 0
    num_medium_vulns = 0
    num_high_vulns = 0
    num_critical_vulns = 0
    num_unassigned_vulns = 0
    
    num_vulns_no_cvss = 0
    num_vulns_cvss = 0
    agreed_cvss_scores = []
    
    for ind, row in selected_rows.iterrows():
        if row['num_cves'] == 0 :
            continue
        for cve in  row['cves']:
            sev = cve['severity'].upper().strip()
            sco = cve["cvssv3_score"].upper().strip()
            
            if sev == "MEDIUM":
                num_medium_vulns += 1
            elif sev == "HIGH":
                num_high_vulns += 1
            elif sev == "LOW":
                num_low_vulns += 1
            elif sev == "CRITICAL":
                num_critical_vulns += 1
            elif sev == "" or sev ==  "UNSPECIFIED" or sev == "UNASSIGNED" or sev == "UNKNOWN":
                num_unassigned_vulns += 1
                
            if sco == "":
                num_vulns_no_cvss += 1
            else:
                sco = float(sco)
                if sco == 0.0:
                    num_vulns_no_cvss += 1
                else:
                    num_vulns_cvss += 1
                    agreed_cvss_scores.append(sco)
    
    scos_arr = np.array(agreed_cvss_scores)
            
    # Remove NaNs from the array
    scos_arr = scos_arr[~np.isnan(scos_arr)]

    # Calculate the average
    average_scos = round(np.mean(scos_arr).item(), 2)
    
    # Check if the array is empty after removing NaNs
    if scos_arr.size == 0:
        average_scos = 0 
    else:
        # Calculate the average
        average_scos = round(np.mean(scos_arr).item(), 2)
     
    if show is True:
        with st.expander("See detailed analysis"):
            st.write("The distribution  of vulnerabilities detected by scanner " + selected_scanner_name + " is:")
            col1, col2, col3 = st.columns(3)
            col1.metric(label ="Number of CRITICAL vulnerabilities", value=num_critical_vulns)
            col2.metric(label ="Number of HIGH vulnerabilities", value=num_high_vulns)
            col3.metric(label ="Number of MEDIUM vulnerabilities", value=num_medium_vulns)
        
            col4, col5 = st.columns(2)
            col4.metric(label ="Number of LOW vulnerabilities", value=num_low_vulns)
            col5.metric(label ="Number of UNASSIGNED vulnerabilities", value=num_unassigned_vulns)
            
            
            col11, col21, col31 = st.columns(3)
            col11.metric(label ="Vulnerabilities with an assigned CVSS V3 Score", value=num_vulns_cvss)
            col21.metric(label ="Vulnerabilities with no assigned CVSS V3 Score", value=num_vulns_no_cvss)
            col31.metric(label ="Average CVSS V3 Score per CVE", value=average_scos)
        
        
            for ind, row in selected_rows.iterrows():
                for cve in  row['cves']:
                    st.markdown("CVE **:red[" + cve["cve_id"]+ "]**:")
                    st.write("Packages: " + ", ".join(cve["package"]))
                    st.write("CVSS V3 Score: " + cve["cvssv3_score"])
                    st.write("Severity: " + cve["severity"])
                    st.write("Type: " + cve["type"])
                    st.write("Is Fixed: " + str(cve["is_fixed"]))
                    st.write("Fixed version: " + cve["fixed_version"])
                
    return num_low_vulns,num_medium_vulns, num_high_vulns, num_critical_vulns, num_unassigned_vulns
                
                
                
def extract_severity(cve_id, scanner_cve_info_obj_df, recompute):
    
    value_sev = ""
    score_cvss = 0.0
        
    diff_severities = []
    diff_cvss_scores = []
    
    for ind, r in scanner_cve_info_obj_df.iterrows():
        
        current_sev = r['severity'].upper().strip()
        current_score = r['cvssv3_score'].upper().strip()
        if current_sev != "":
            diff_severities.append(current_sev)
        if current_score != "":
            current_score = float(current_score)
            if current_score != 0.0 :
                diff_cvss_scores.append(current_score)
    
    diff_severities = set(diff_severities)
    diff_cvss_scores = set(diff_cvss_scores)
    
    if len(diff_severities) > 1:
        diff_severities = solve_diff_sevs(diff_severities)

    if len(diff_severities) == 0:
        #st.metric(label="Severity of this vulnerability", value="UNASIGNED")
        value_sev = "UNASSIGNED"
        
        #if recompute is True:
            ###severity_recom, score_recom = get_cve_details(cve_id)
            ##if severity_recom:
                #print("recomputed sev: ", severity_recom)
                #value_sev = severity_recom.upper().strip()
            #else:
                #print("Failed to retrieve CVE details. for cve id: ", cve_id)
    
    elif len(diff_severities) >  1:
        #diff_severities = ', '.join(diff_severities)
        #st.markdown("   :red[Different severities were assigned by different scanners for this vulnerability:]")
        #st.write("      "+diff_severities)
        value_sev = "DIFFERING"
        if recompute is True:
            severity_recom, score_recom = get_cve_details(cve_id)
            if severity_recom:
                #print("recomputed sev: ", severity_recom)
                value_sev = severity_recom.upper().strip()
            #else:
                #print("Failed to retrieve CVE details. for cve id: ", cve_id)
    else:
        #st.metric(label="Severity of this vulnerability", value=list(diff_severities)[0])
        val =  list(diff_severities)[0]
        if val == "MEDIUM":
            value_sev = "MEDIUM"
        elif val == "HIGH":
            value_sev = "HIGH"
        elif val == "LOW":
            value_sev = "LOW"
        elif val == "CRITICAL":
            value_sev = "CRITICAL"
        elif val == "UNASSIGNED":
            value_sev = "UNASSIGNED"
        elif val == "UNSPECIFIED":
            value_sev = "UNASSIGNED"
        elif val == "UNKNOWN":
            value_sev = "UNASSIGNED"
        else: 
            print("UNKNWO SEV VVALUE: ")
            print(val)
            
    if len(diff_cvss_scores) == 0:
        #st.metric(label="CVSS V3 Score for this vulnerability", value="UNASSIGNED")
        #num_vulns_no_cvss += 1
        score_cvss = 0.0
    elif len(diff_cvss_scores) >  1:
        #st.markdown("   :red[Different CVSS V3 scores were assigned by different scanners for this vulnerability:]")
        score_cvss = -1.0
    else:
        score_cvss = list(diff_cvss_scores)[0]
        
    return value_sev, score_cvss


def get_cve_details(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {
        "apiKey": NVD_API_KEY
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        cve_data = response.json()
        
        if 'vulnerabilities' in cve_data and cve_data['vulnerabilities']:
            cve_item = cve_data['vulnerabilities'][0]['cve']
            
            if 'metrics' in cve_item:
                metrics = cve_item['metrics']
                if 'cvssMetricV31' in metrics:
                    severity = None
                    score = None
                    cvss_v3 = metrics['cvssMetricV31'][0]['cvssData']
                    if 'baseSeverity' in cvss_v3:
                        severity =cvss_v3['baseSeverity']
                    if 'baseScore'in cvss_v3:
                        score = cvss_v3['baseScore']
                    return severity, score
                elif 'cvssMetricV30' in metrics:
                    severity = None
                    score = None
                    cvss_v3 = metrics['cvssMetricV30'][0]['cvssData']
                    if 'baseSeverity' in cvss_v3:
                        severity =cvss_v3['baseSeverity']     
                    if 'baseScore'in cvss_v3:
                        score = cvss_v3['baseScore']
                    return severity, score
                elif 'cvssMetricV2' in metrics:
                    severity = None
                    score = None
                    cvss_v2 = metrics['cvssMetricV2'][0]['cvssData']
                    if 'baseSeverity' in cvss_v2:
                        severity = cvss_v2['baseSeverity'] 
                    if 'baseScore'in cvss_v2:
                        score = cvss_v2['baseScore']
                    return severity, score
                else:
                    return None, None
            else:
                return None, None
    #else:
        #print(f"Failed to fetch CVE details: {response.status_code}")
    
    return None, None

def process_file(filename):
    with open(filename) as file:
        dataJSON = json.load(file)
        
    num_unique_cves = dataJSON["num_unique_cves"]
    image_name = dataJSON["image_scanned"]
    df1 = pd.json_normalize(dataJSON, 'cves_detected_all_scanners')
    df2 = pd.json_normalize(dataJSON, 'unique_cves')
    
    return df1, df2, num_unique_cves, image_name

def extract_packages(scanner_cve_info_obj_df):
    
    pkg_list = set()
    for ind, r in scanner_cve_info_obj_df.iterrows():
        current_pkgs = r['package']
        scanner = r['scanner_name']
        
    
        current_pkgs = current_pkgs.split(',')

        for pkg in current_pkgs:
            pkg = pkg.strip()
            if scanner == "Trivy":
                s = pkg.split(' ')
                if len(s) > 1:
                    final_pkg = pkg.split(' ')[1]
                else:
                    final_pkg = s[0]
            elif scanner == "Grype":
                final_pkg = pkg
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
            
    pkg_list = list(pkg_list)
    final_pkg_set = set()
    for i in range(len(pkg_list)):
        check = False
        for j in range(0, len(pkg_list)):
            if j == i:
                continue
            if pkg_list[i] in pkg_list[j]:
                check = True
        if check == False:
            final_pkg_set.add(pkg_list[i])
            
            
    return final_pkg_set

def extract_types(scanner_cve_info_obj_df):
    
    diff_types_set = set()
    type_val = set()
    
    for ind, r in scanner_cve_info_obj_df.iterrows():
        typ = r['type']
        list_langs = ["go-module", "python", "npm", "rust-crate", 
                                      "gem", "java-archive", "dotnet", "php-pecl", 
                                      "php-composer"]
        list_os = ["deb", "apk", "rpm", "linux-kernel"] 
                        
        if typ != "":
            if typ in list_os:
                typ = "OsPackageVulnerability"
            if typ in list_langs:
                typ = "LanguageSpecificPackageVulnerability"
            
            diff_types_set.add(typ)
            
    if len(diff_types_set) == 0:
        type_val.add("UNASSIGNED")
    elif len(diff_types_set) == 1:
        type_val.add(list(diff_types_set)[0])
    elif len(diff_types_set) > 1:
        #types_sorted = sorted(list(diff_types_set))
        #type_val.add(",".join(types_sorted))
        type_val.update(diff_types_set)
  
    return type_val

def extract_fix_status(scanner_cve_info_obj_df): # Per CVE ID
    # Check if all fixed statuses and versions are the same
    
    set_fixed = set()
    set_versions = set()
    
    for ind, r in scanner_cve_info_obj_df.iterrows():
        scanner = r['scanner_name']
        is_fixed = r['is_fixed']
        fixed_version = r['fixed_version']
        
        set_fixed.add(is_fixed)
        set_versions.add(fixed_version)
        

    if len(set_fixed) == 1: # means that for this CVE, fixed statuses are equal for all scanner
        if list(set_fixed)[0] is True:
            return "fixed"
        elif list(set_fixed)[0] is False:
            return "not_fixed"
    elif len(set_versions) > 1:
        return "different_statuses" # means that for this CVE, fixed statuses differ by scanner

    return "not_fixed"

def compute_severities_by_scanner(cves_list):
    
    fixed_string = cves_list.replace("'", '"')
    fixed_string = fixed_string.replace("True", "true").replace("False", "false")
    cves_list_fix = json.loads(fixed_string)
    
    num_low_vulns = 0
    num_medium_vulns = 0
    num_high_vulns = 0
    num_critical_vulns = 0
    num_unassigned_vulns = 0
    
    num_vulns_no_cvss = 0
    num_vulns_cvss = 0
    agreed_cvss_scores = []

    for cve in cves_list_fix:
        sev = cve["severity"].upper().strip()
        sco = cve["cvssv3_score"].upper().strip()
        
        if sev == "MEDIUM":
            num_medium_vulns += 1
        elif sev == "HIGH":
            num_high_vulns += 1
        elif sev == "LOW":
            num_low_vulns += 1
        elif sev == "CRITICAL":
            num_critical_vulns += 1
        elif sev == "UNASSIGNED":
            num_unassigned_vulns += 1
        elif sev == "UNSPECIFIED":
            num_unassigned_vulns += 1
        elif sev == "UNKNOWN":
            num_unassigned_vulns += 1
        elif sev == "":
            num_unassigned_vulns += 1
        else: 
            print("severity VALUE UKNOWN: ")
            print(sev)
            
        if sco == "":
            num_vulns_no_cvss += 1
        else:
            sco = float(sco)
            if sco == 0.0:
                num_vulns_no_cvss += 1
            else:
                num_vulns_cvss += 1
                agreed_cvss_scores.append(sco)
            
    scos_arr = np.array(agreed_cvss_scores)
    average_scos = round(np.mean(scos_arr).item(),2)
        
    return num_low_vulns, num_medium_vulns, num_high_vulns, num_critical_vulns, num_unassigned_vulns, num_vulns_cvss, num_vulns_no_cvss, average_scos

def compute_severities_by_scanner_mod(cves_list):
        
    num_low_vulns = 0
    num_medium_vulns = 0
    num_high_vulns = 0
    num_critical_vulns = 0
    num_unassigned_vulns = 0
    
    num_vulns_no_cvss = 0
    num_vulns_cvss = 0
    agreed_cvss_scores = []

    for cve in cves_list:
        sev = cve["severity"].upper().strip()
        sco = cve["cvssv3_score"].upper().strip()
        
        if sev == "MEDIUM":
            num_medium_vulns += 1
        elif sev == "HIGH":
            num_high_vulns += 1
        elif sev == "LOW":
            num_low_vulns += 1
        elif sev == "CRITICAL":
            num_critical_vulns += 1
        elif sev == "UNASSIGNED":
            num_unassigned_vulns += 1
        elif sev == "UNSPECIFIED":
            num_unassigned_vulns += 1
        elif sev == "UNKNOWN":
            num_unassigned_vulns += 1
        elif sev == "":
            num_unassigned_vulns += 1
        else: 
            print("severity VALUE UKNOWN: ")
            print(sev)
            
        if sco == "":
            num_vulns_no_cvss += 1
        else:
            sco = float(sco)
            if sco == 0.0:
                num_vulns_no_cvss += 1
            else:
                num_vulns_cvss += 1
                agreed_cvss_scores.append(sco)
            
    scos_arr = np.array(agreed_cvss_scores)
    average_scos = round(np.mean(scos_arr).item(),2)
        
    return num_low_vulns, num_medium_vulns, num_high_vulns, num_critical_vulns, num_unassigned_vulns, num_vulns_cvss, num_vulns_no_cvss, average_scos


def packages_by_scanner(scanner, cves_list):
    
    fixed_string = cves_list.replace("'", '"')
    fixed_string = fixed_string.replace("True", "true").replace("False", "false")
    cves_list_fix = json.loads(fixed_string)
    
    pkg_dict = {}

    for cve in cves_list_fix:
        pkgs = cve["package"]
        
        for pkg in pkgs:
            pkg = pkg.strip()
            if scanner == "Trivy":
                s = pkg.split(' ')
                if len(s) > 1:
                    final_pkg = pkg.split(' ')[1]
                else:
                    final_pkg = s[0]
            elif scanner == "Grype":
                final_pkg = pkg
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
            
            if final_pkg in pkg_dict:
                pkg_dict[final_pkg] += 1
            else:
                pkg_dict[final_pkg] = 1
        
    return pkg_dict

def packages_by_scanner_mod(scanner, cves_list):
    
    
    pkg_dict = {}

    for cve in cves_list:
        pkgs = cve["package"]
        
        for pkg in pkgs:
            pkg = pkg.strip()
            if scanner == "Trivy":
                s = pkg.split(' ')
                if len(s) > 1:
                    final_pkg = pkg.split(' ')[1]
                else:
                    final_pkg = s[0]
            elif scanner == "Grype":
                final_pkg = pkg
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
            
            if final_pkg in pkg_dict:
                pkg_dict[final_pkg] += 1
            else:
                pkg_dict[final_pkg] = 1
        
    return pkg_dict

def fix_statuses_by_scanner(cves_list):
    fixed_string = cves_list.replace("'", '"')
    fixed_string = fixed_string.replace("True", "true").replace("False", "false")
    cves_list_fix = json.loads(fixed_string)

    num_fixed = 0
    num_not_fixed = 0
    
    for cve in cves_list_fix:
        fixed_stat = cve["is_fixed"]
        
        if fixed_stat is True:
            num_fixed += 1
        else:
            num_not_fixed += 1
            
    return num_fixed, num_not_fixed

def fix_statuses_by_scanner_mod(cves_list):


    num_fixed = 0
    num_not_fixed = 0
    
    for cve in cves_list:
        fixed_stat = cve["is_fixed"]
        
        if fixed_stat is True:
            num_fixed += 1
        else:
            num_not_fixed += 1
            
    return num_fixed, num_not_fixed

def combine_dicts(new_dict, dict2):
    
    for key, value in new_dict.items():
        if key in dict2:
            dict2[key] = dict2[key] + value
        else:
            dict2[key] = value
            
def process_image(df_unique_cves):
    
    final_pkg_list = set()
    num_unique_cves = len(df_unique_cves)
    num_low_vulns = 0
    num_medium_vulns = 0
    num_high_vulns = 0
    num_critical_vulns = 0
    num_unassigned_vulns = 0
    num_diff_vulns = 0
    
    for index, row in df_unique_cves.iterrows():
        i = row['scanner_cve_info']
        i_df = norm_unique_cves_field(i)
            
        diff_severities = []
        diff_cvss_scores = []
        pkg_list = set()

        for ind, r in i_df.iterrows():
            packages = r['package']
            pkgs = packages.split(',')
            scanner = r['scanner_name'] 
            
            for pkg in pkgs:
                pkg = pkg.strip()
                if scanner == "Trivy":
                    final_pkg = pkg.split(' ')[1]
                elif scanner == "Grype":
                    final_pkg = pkg
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
        
        
        pkg_list = list(pkg_list)
        for i in range(len(pkg_list)):
            check = False
            for j in range(0, len(pkg_list)):
                if j == i:
                    continue
                if pkg_list[i] in pkg_list[j]:
                    check = True
            if check == False:
                final_pkg_list.add(pkg_list[i])
        
        diff_severities = set(diff_severities)
        diff_cvss_scores = set(diff_cvss_scores)
        
        if len(diff_severities) > 1:
            diff_severities = solve_diff_sevs(diff_severities)

        if len(diff_severities) == 0:
            num_unassigned_vulns += 1
        elif len(diff_severities) >  1:
            num_diff_vulns += 1
        else:
            val =  list(diff_severities)[0]
            if val == "MEDIUM":
                num_medium_vulns += 1
            elif val == "HIGH":
                num_high_vulns += 1
            elif val == "LOW":
                num_low_vulns += 1
            elif val == "CRITICAL":
                num_critical_vulns += 1
            elif val == "UNASSIGNED":
                num_unassigned_vulns += 1
            elif val == "UNSPECIFIED":
                num_unassigned_vulns += 1
            elif val == "UNKNOWN":
                num_unassigned_vulns += 1
            elif val == "":
                num_unassigned_vulns += 1
            
    
        #if len(diff_cvss_scores) == 0:
            #st.metric(label="CVSS V3 Score for this vulnerability", value="UNASIGNED")
       #elif len(diff_cvss_scores) >  1:
           # diff_cvss_scores = ', '.join([str(num) for num in diff_cvss_scores])
            #st.markdown("   :red[Different CVSS V3 scores were assigned by different scanners for this vulnerability:]")
            #st.write("      "+diff_cvss_scores)
        #else:
            #st.metric(label="CVSS V3 Score for this vulnerability", value=list(diff_cvss_scores)[0])
    
    
    return num_unique_cves, final_pkg_list, num_low_vulns, num_medium_vulns, num_high_vulns, num_critical_vulns, num_unassigned_vulns, num_diff_vulns


def get_metadata(img_name, type_files, df_official, df_verified, df_sponsored):
    
    s = img_name.split(':')
    img = s[0]
    tag = s[1]
    result_df = pd.DataFrame()
    
    if type_files == "Official Images":
        result_df = df_official[(df_official['Name'] == img) & (df_official['TagName'] == tag)]
    elif type_files == "Verified Images":
        s = img.split('/')
        repo = s[0]
        n = s[1]
        result_df = df_verified[(df_verified['Name'] == n) & (df_verified['TagName'] == tag) & (df_verified['Repository'] == repo)]
    elif type_files == "Sponsored Images":
        s = img.split('/')
        repo = s[0]
        n = s[1]
        result_df = df_sponsored[(df_sponsored['Name'] == n) & (df_sponsored['TagName'] == tag) & (df_sponsored['Repository'] == repo)]
        
    if len(result_df) != 1:
        print(result_df)
        raise RuntimeError("result_df len is diff than 1: " + str(len(result_df)) + "for img: " + img + " and tag: " + tag)
        
    c = result_df.iloc[0]['Category']
    sta = result_df.iloc[0]['StarCount']
    p = result_df.iloc[0]['PullCount']
    sub = result_df.iloc[0]['SubCategories']
    size = result_df.iloc[0]['TagSize']
    
    return c, sta, p, sub, size

def norm_unique_cves_field(scanner_cve_info):
    # Initialize lists to store extracted data
    scanner_names = []
    cve_ids = []
    packages = []
    cvssv3_scores = []
    severities = []
    types = []
    is_fixeds = []
    fixed_versions = []

    # Extract data from each dictionary in 'scanner_cve_info'
    for item in scanner_cve_info:
        scanner_names.append(item['scanner_name'])
        cve_ids.append(item['cve_info']['cve_id'])
        # Convert list to comma-separated string
        packages.append(', '.join(item['cve_info']['package']))
        cvssv3_scores.append(item['cve_info']['cvssv3_score'])
        severities.append(item['cve_info']['severity'])
        types.append(item['cve_info']['type'])
        is_fixeds.append(item['cve_info']['is_fixed'])
        fixed_versions.append(item['cve_info']['fixed_version'])

    # Create DataFrame
    df = pd.DataFrame({
        'scanner_name': scanner_names,
        'cve_id': cve_ids,
        'package': packages,
        'cvssv3_score': cvssv3_scores,
        'severity': severities,
        'type': types,
        'is_fixed': is_fixeds,
        'fixed_version': fixed_versions
    })

    return df

def compute_stats(list_scanner):
    data_array = np.array(list_scanner)
    
    
    average= np.mean(data_array).item()
    median = np.median(data_array).item()
    variance = np.var(data_array, ddof=1).item()  # ddof=1 for sample variance
    std_dev = np.std(data_array, ddof=1).item()  # ddof=1 for sample standard deviation
    min_value = np.min(data_array).item()
    max_value = np.max(data_array).item()
    range_value = max_value - min_value
    
    return average, median, variance, std_dev, min_value, max_value, range_value


def solve_diff_sevs(diff_severities_set):
    diff_sevs = list(diff_severities_set)
    
    final_set = set()
    
    for sev in diff_sevs:
        if sev != "UNASSIGNED":
            final_set.add(sev)
            
    return final_set
            