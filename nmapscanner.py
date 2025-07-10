import subprocess
import re
import xml.etree.ElementTree as ET
import requests
from fuzzywuzzy import fuzz
import json
from datetime import datetime




class NmapScanner:
    def __init__(self,target,normal_ports=None,nmap_path=r'C:\Program Files (x86)\Nmap\nmap.exe', api_key=None):
        self.target =  target
        self.nmap_path = nmap_path
        self.normal_ports_set = normal_ports if normal_ports else {80,53}
        self.normal_ports = []
        self.abnormal_ports =[]
        #new
        self.xml_output = "scan_output.xml"
        self.cpes =[]
        self.api_key = api_key
        
        
    
    def run_scan(self):
        command = [self.nmap_path,'-sV','-oX',self.xml_output, self.target]
        result = subprocess.run(command,capture_output =True,text=True)
        if result.returncode ==0:
            self._parse_output(result.stdout)
                        #NEW
            self._parse_cpes_from_xml()
           
            return True
        else:
            print("Nmap Scan failed!")
            print(result.stderr)
            return False
        
        
    def run_UDP_fullscan(self):
        command = [self.nmap_path, "-6", "-sU", "-sV", "-p-", self.target]
        result = subprocess.run(command,capture_output =True,text=True)
        if result.returncode ==0:
            self._parse_output(result.stdout)

        else:
            print("UDP full scan failed!")
            print(result.stderr)
            return False
        
    def run_TCP_fullscan(self):
        command = [self.nmap_path, "-6", "-sT", "-sV", "-p-", self.target]
        result = subprocess.run(command,capture_output =True,text=True)
        if result.returncode ==0:
            self._parse_output(result.stdout)
            return True
        else:
            print("TCP Full Scan failed!")
            print(result.stderr)
            return False

        
    def _parse_output(self,output):
        lines = output.split('\n')
        for line in lines:
            if re.match(r'^(\d+)/tcp',line.strip()):
                port = int(re.match(r'^(\d+)/tcp',line.strip()).group(1))
                if port in self.normal_ports_set:
                    self.normal_ports.append(line)
                else: 
                    self.abnormal_ports.append(line)
    # This fucntion parses CPE which are in CPE 2.2 format from the nmap command ran using  -oX to gernerate output          
    def _parse_cpes_from_xml(self):
        try: 
            tree = ET.parse(self.xml_output)
            root = tree.getroot()
            for service in root.findall(".//service"):
                cpe_elements = service.findall("cpe")
                for cpe in cpe_elements: 
                    self.cpes.append(cpe.text)
        except Exception as e: 
            print(f"Error parsing XML:{e}")
            
    # This function converts CPE 2.2 to 2.3 format
    def convert_cpe_2_2_to_2_3(self,cpe_2_2):
        parts = cpe_2_2.replace("cpe:/","").split(":")
        while len(parts)<11:
            parts.append("*")
        return f"cpe:2.3:{':'.join(parts)}"
    
    def generate_wildcarded_cpe(cpe_23):
        parts = cpe_23.split(":")
        if len(parts) >= 5:
            parts[4] = "*"  # Replace version
            return ":".join(parts)
        return cpe_23  # Return as-is if malformed
 
    # This function takes in the specific CPE 23 and Queries NVD API
    # Returns result in JSON format including vulnerability Information
    def query_nvd_api(self, cpe_23, api_key):
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {"apiKey": api_key} if api_key else {}
        params = {
            "cpeName": cpe_23,
            "resultsPerPage":2
            }
        

        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            vulns.sort(
                key=lambda x: datetime.strptime(
                    x.get("cve", {}).get("published", "1900-01-01T00:00:00.000"),
                    "%Y-%m-%dT%H:%M:%S.%f"
                ),
                reverse=True
    )
            vendor = cpe_23.split(":")[3] if len(cpe_23.split(":")) > 3 else "N/A"
            product = cpe_23.split(":")[4] if len(cpe_23.split(":")) > 4 else "N/A"
            version = cpe_23.split(":")[5] if len(cpe_23.split(":")) > 5 else "N/A"

            if not vulns:
                return {
                    "cpe": cpe_23,
                    "product": product,
                    "version": version,
                    "vulnerable": False,
                    "message": "No vulnerabilities found",
                    "vulnerabilities": []
                }

            result = {
                "cpe": cpe_23,
                "product": product,
                "version": version,
                "vulnerable": True,
                "vulnerabilities": []
            }

            for item in vulns:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "N/A")
                            
                descriptions = cve.get("descriptions", [])
                summary = next(
                    (d.get("value") for d in descriptions if d.get("lang") == "en"),
                    "No description"
                )
                metrics = cve.get("metrics", {})

                cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                cvss_v30 = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                cvss_v20 = metrics.get("cvssMetricV20", [{}])[0].get("cvssData", {})

                cvss_info = {
                    "v3.1": {
                        "score": cvss_v31.get("baseScore", "N/A"),
                        "severity": cvss_v31.get("baseSeverity", "N/A")
                    },
                    "v3.0": {
                        "score": cvss_v30.get("baseScore", "N/A"),
                        "severity": cvss_v30.get("baseSeverity", "N/A")
                    },
                    "v2.0": {
                        "score": cvss_v20.get("baseScore", "N/A"),
                        "severity": cvss_v20.get("severity", "N/A")  # v2 uses "severity"
                    }
                }
                
                published_date = cve.get("published", "N/A")

                references = cve.get("references", [])
                source_url = references[0].get("url") if references else "N/A"

                result["vulnerabilities"].append({
                    "cve_id": cve_id,
                    "description":summary,
                    "cvss_info" :cvss_info,
                
                    "published_date":published_date,
                    "source": source_url
                })
            return result

        except requests.HTTPError as e:
            return {"error": f"HTTP error querying NVD API: {e}"}
        except requests.ConnectionError:
        
            return {"error": "Failed to connect to NVD API. The service may be down."}
        except requests.Timeout:
            
                return {"error": "Request to NVD API timed out. The service may be down or slow."}
        except Exception as e:
            return {"error": f"Unexpected error: {e}"}
     

    # Function that parse CPE official dictionary and extracts usable CPE entries for list
    # Useful CPE entries include CPE 2.3 non- deprecated replacement 
    # Skips Deprecated items unless have replacements 
    def parse_cpe_dictionary(self, cpe_file_path):
        cpes = []
        replacements = []

        try:
            tree = ET.parse(cpe_file_path)
            root = tree.getroot()

            namespaces = {
                'cpe-23': 'http://scap.nist.gov/schema/cpe-extension/2.3'
            }

            for cpe in root.findall(".//cpe-23:cpe23-item", namespaces):
                name = cpe.get("name")
                deprecation = cpe.find("cpe-23:deprecation", namespaces)

                if deprecation is not None:
                
                    replacement = deprecation.find("cpe-23:deprecated-by", namespaces)
                    if replacement is not None:
                        replacement_name = replacement.get("name")
                        if replacement_name:
                            replacements.append(replacement_name)
                    continue 

                if name:
                    cpes.append(name)

            
            seen = set(cpes)
            for r in replacements:
                if r not in seen:
                    cpes.append(r)
                    seen.add(r)

            print(f"Found {len(cpes)} usable CPEs (including replacements).")
            return cpes
        except Exception as e:
            print(f"Error parsing CPE dictionary: {e}")
            return []
    def split_cpe(self,cpe):
        parts = cpe.split(":")
        vendor = parts[3] if len(parts) > 3 else ""
        product = parts[4] if len(parts) > 4 else ""
        version = parts[5] if len(parts) > 5 else ""
        return vendor, product, version
    
    # Function to find attemps to find the closest matching CPE entry from a list using fuzzy string matching
    # Scores weighted heavily through product matching 
    
    def fuzzy_match_cpe(self,cpe_to_match: str, cpe_list: list, min_score=65):
        v, p, ver = self.split_cpe(cpe_to_match)
        best_score = 0
        best_cpe = None

        for candidate in cpe_list:
            cv, cp, cver = self.split_cpe(candidate)

            vendor_score = fuzz.ratio(v, cv)
            product_score = fuzz.ratio(p, cp)
            version_score = fuzz.ratio(ver, cver)

        
            combined_score = 0.3 * vendor_score + 0.5 * product_score + 0.2 * version_score

            if combined_score > best_score:
                best_score = combined_score
                best_cpe = candidate

        if best_score >= min_score:
            return best_cpe, best_score
        else:
            return None, 0

    def is_cpe_qualified(self, cpe_23: str) -> bool:
        parts = cpe_23.split(":")
        if len(parts) > 5 and parts[5] != "*" and parts[5] != "":
            return True
        return False
                        
    def print_results(self):
        if self.normal_ports or self.abnormal_ports:
            print("\n===Normal===")
            print("\n".join(self.normal_ports) if self.normal_ports else "No normal ports found")
            print("\n===Abnormal===")
            print("\n".join(self.abnormal_ports) if self.abnormal_ports else "No abnormal ports found")
        else:
            print("No open ports found")
        print("\nNmap Scan was successful")
        print("\n=== Extracted CPEs and Vulnerabilities ===")
        cpe_dict = self.parse_cpe_dictionary(r"C:\Users\Offband\Documents\official-cpe-dictionary_v2.3.xml")     
        if not self.cpes:
            print("\n⚠️  No CPEs with specific version information were extracted from the Nmap scan.")
            print("This means the scan did not detect services with identifiable product + version info mapped to official CPEs.")
            print("Without a CPE that includes an exact version, no CVE-based vulnerability analysis can be performed.")
            print("As a result, we cannot confirm or deny the presence of known vulnerabilities for these services.")
            print()
            return

        for cpe_23 in self.cpes:

                
            converted_cpe= self.convert_cpe_2_2_to_2_3(cpe_23)
            
            print(f"\nChecking CPE: {converted_cpe}")
            if not self.is_cpe_qualified(converted_cpe):
                print("\n" + "="*150)
                print(f"Service '{converted_cpe}' does not have a specific version. You may need to find the version and manually look it up.")
                print("="*150 + "\n")


            else:
            
                result = self.query_nvd_api(converted_cpe, self.api_key)
            

                if result.get("error") or not result.get("vulnerable"):
                    print(f"Trying fuzzy match correction for {converted_cpe}..")
                    closest_match, score = self.fuzzy_match_cpe(converted_cpe, cpe_dict)
                    if closest_match:
                        print(f"\n Results")
                        print(f"\nClosest CPE: {closest_match} (score {score})")
                        result = self.query_nvd_api(closest_match, self.api_key)
                    else:
                        print("No good fuzzy match found.")
                print("="*150 + "\n")
                print(json.dumps(result, indent=2))
                print("="*150 + "\n")
                
           
