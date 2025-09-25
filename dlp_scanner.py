#import modules
import os #importing os for walking through directories/files
import re #importing regex for the expressions to detect PII patterns
from docx import Document #importing Document from docx library to read through .docx files
from jinja2 import Template #importing Template from jinja2 to generate a HTML report
import webbrowser #importing webbrowser to open the report locally on the default web browser


#set up
FOLDERS_TO_SCAN = [os.path.expanduser("~/Desktop"), os.path.expanduser("~/Downloads"), os.path.expanduser("~/Documents")]  #sets it to the user's home directory path + the different folder paths to scan
MAX_FILE_SIZE_MB = 10 #sets max file size to 10 mb to avoid slow run time and big files
REPORT_PATH = os.path.expanduser("~/Desktop/pii_report.html") #where the HTML report will be created on the user's computer (their desktop)


#regex list
PII_PATTERNS = {
   "Email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", #matches email addresses for word + @ + domain + 2+ letter TLD
   "Phone Number": r"\b(?:\+?1[-.\s]?)*\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", #matches optional country code, area code, +7 digit number
   "Social Security Number": r"\b\d{3}-\d{2}-\d{4}\b", #matches xxx-xx-xxxx digit format with hyphens included
   "Credit Card": r"\b(?:4\d{3}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}|5[1-5]\d{2}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}|3[47]\d{2}[- ]?\d{6}[- ]?\d{5})\b", #matches credit cards: Visa (starts w/ 4), Mastercard (starts w/ 51-55), AmEx (starts w/ 34 or 37)
   "Address": r"\b\d{1,5}\s(?:[A-Za-z0-9]+\s){1,5}?(?:St|Street|Ave|Avenue|Blvd|Boulevard|Rd|Road|Ln|Lane|Dr|Drive)\b", #matches 1-5 digit number, words, + ends in street suffix
   "Driver's License": r"\b(?:[A-Z]\d{7}|\d{8})\b", #matches either 1 capital letter + 7 numbers or exactly 8 digit number
   "Tax Identification Number (TIN)": r"\b\d{2}-\d{7}\b", #matches 2 digits + dash + 7 digits
   "Passport Number": r"\b(?:[A-Z]{1}\d{8}|\d{9})\b", #matches either 1 letter + 8 digits or exactly 9 digits
   "IP Address": r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b", #matches 4 octets (0-255) separated by '.'
   "Date of Birth": r"\b(?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12][0-9]|3[01])[-/](?:\d{2}|\d{4})\b" #matches for MM/DD/YYYY or M/D/YY
}




#file reading methods
def extract_txt_text(file_path): #extracting text from .txt file
   try:
       with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
           return f.read()  #returns file contents as a string
   except Exception as e: #returns empty string if file cannot be read properly
       return ""


def extract_docx_text(file_path): #extracting text from .docx file
   try:
       doc = Document(file_path) #opens .docx contents
       return "\n".join([p.text for p in doc.paragraphs]) #joins all paragraph texts into one string
   except Exception as e: #returns empty string if file cannot be read properly
       return ""


from PyPDF2 import PdfReader #imports PDF reader class from PyPDF2 module, we need this because pdf files aren't just text


def extract_pdf_text(file_path): #extracting text from .pdf file
   try:
       reader = PdfReader(file_path)
       text = "" #initialize empty string to hold combined page texts
       for page in reader.pages:
           text += page.extract_text() or "" #adds text for each page
       return text #returns combined text from all pages from file
   except Exception as e: #returns empty string if file cannot be read properly
       return ""


#main scanner
def scan_files():
   results = [] #initialize empty list store PII findings for final output
   for folder in FOLDERS_TO_SCAN: #loops through specified directories
       for root, _, files in os.walk(folder): #walks through directories
           for file in files: #iterates through all files in the current directory
               full_path = os.path.join(root, file) #gets the full path of the current file
               if os.path.getsize(full_path) > MAX_FILE_SIZE_MB * 1024 * 1024: #only iterates through files under the max size limit
                   continue
               #runs the methods associated with the file type and extracts text
               if file.endswith(".txt"):
                   text = extract_txt_text(full_path)
               elif file.endswith(".docx"):
                   text = extract_docx_text(full_path)
               elif file.endswith(".pdf"):
                   text = extract_pdf_text(full_path)
               else:
                   continue #skips other file types that are not ".txt", ".docx", or ".pdf"


               findings = [] # temp list to hold PII matches for the file
               for label, pattern in PII_PATTERNS.items(): #loops through each PII pattern defined in above section
                   matches = re.findall(pattern, text) #uses regex and finds matches
                   if matches:
                       findings.append((label, list(set(matches)))) #stores the label (name of PII) and matched strings


               if findings:
                   results.append({ #adds file path and findings to the results list if PII was found
                       "file": full_path,
                       "matches": findings
                   })
   return results




#generate report
def generate_report(results):
   #define PII priority in order of importance
   pii_priority = {
       "Social Security Number": 10,
       "Passport Number": 9,
       "Driver's License": 8,
       "Credit Card": 7,
       "Tax Identification Number (TIN)": 6,
       "Address": 5,
       "IP Address": 4,
       "Phone Number": 3,
       "Email": 2,
       "Date of Birth": 1
   }


   #process results for better readability + presentation for the report
   processed_results = []
   for item in results: #loops through scanned file's results
       #extracts file and directory name separately
       file_name = os.path.basename(item["file"])
       dir_name = os.path.dirname(item["file"])


       #calculate highest priority PII in this file (for risk assessment)
       highest_priority = 0 #initializing variable for highest priority ranking
       for label, _ in item["matches"]: #iterates through PII labels and gets the highest priority score from that file
           priority = pii_priority.get(label, 0)
           highest_priority = max(highest_priority, priority)


       #sorts matches by priority in descending order to make sure critical PII appears first on the report
       sorted_matches = sorted(
           item["matches"],
           key=lambda x: pii_priority.get(x[0], 0),
           reverse=True
       )
       #structured dictionary (file path, file name, directory name, sorted list of PIIs, highest priority) for each file
       processed_results.append({
           "file_path": item["file"],
           "file_name": file_name,
           "dir_name": dir_name,
           "matches": sorted_matches,
           "highest_priority": highest_priority,
           "total_findings": sum(len(matches) for _, matches in item["matches"]) #counts number of total PII findings
       })


   #sorts list of processed results by highest priority PII first, then by files with more total findings
   processed_results.sort(key=lambda x: (x["highest_priority"], x["total_findings"]), reverse=True)


   #gets current date/time to show when the report was generated
   from datetime import datetime
   scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


   #using jinja2 template for the HTML report
   template = Template("""
   <!DOCTYPE html>
   <html lang="en">
   <head>
       <meta charset="UTF-8">
       <meta name="viewport" content="width=device-width, initial-scale=1.0">
       <title>PII Detection Report</title>
       <style>
           :root {
               --primary: #1a73e8;
               --primary-dark: #0d47a1;
               --warning: #e65100;
               --danger: #d32f2f;
               --success: #388e3c;
               --text-dark: #333;
               --text-light: #666;
               --bg-light: #f8f9fa;
               --card-shadow: 0 2px 8px rgba(0,0,0,0.1);
           }


           * {
               box-sizing: border-box;
               margin: 0;
               padding: 0;
               font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', sans-serif;
           }


           body {
               background-color: var(--bg-light);
               color: var(--text-dark);
               line-height: 1.6;
               padding: 20px;
               max-width: 1200px;
               margin: 0 auto;
           }


           .header {
               background: linear-gradient(135deg, var(--primary), var(--primary-dark));
               color: white;
               padding: 30px;
               border-radius: 8px;
               margin-bottom: 30px;
               box-shadow: var(--card-shadow);
           }


           .header h1 {
               margin: 0;
               font-size: 28px;
           }
          
           <!--for the generated reports stats (time/date + total files)-->
           .summary {
               margin-top: 10px;
               font-size: 16px;
               opacity: 0.9;
           }
          
           <!--file cards for aesthetics, going to separate by risk levels and different color codings-->
           .file-card {
               background: white;
               border-radius: 8px;
               padding: 20px;
               margin-bottom: 20px;
               box-shadow: var(--card-shadow);
               border-left: 5px solid var(--primary);
           }


           .file-card.high-risk {
               border-left: 5px solid var(--danger);
           }


           .file-card.medium-risk {
               border-left: 5px solid var(--warning);
           }


           .file-header {
               display: flex;
               justify-content: space-between;
               align-items: flex-start;
               margin-bottom: 10px;
               flex-wrap: wrap;
           }


           .file-title {
               flex: 1;
           }
          
           <!--shows file name and its path separately on the file card-->
           .file-name {
               font-weight: bold;
               font-size: 18px;
               word-break: break-all;
           }


           .file-path {
               color: var(--text-light);
               font-size: 14px;
               margin-top: 4px;
               word-break: break-all;
           }
          
           <!--colored badges show the highest risk level of the file-->
           .risk-badge {
               padding: 4px 12px;
               border-radius: 20px;
               font-size: 12px;
               font-weight: 600;
               color: white;
               background-color: var(--primary);
               margin-left: 15px;
               white-space: nowrap;
           }


           .risk-badge.high {
               background-color: var(--danger);
           }


           .risk-badge.medium {
               background-color: var(--warning);
           }


           .risk-badge.low {
               background-color: var(--success);
           }




           <!--formats list of PII findings for each file and the type with matched values-->
           .pii-list {
               list-style-type: none;
               margin-top: 15px;
           }


           .pii-item {
               padding: 10px;
               border-bottom: 1px solid #eee;
           }


           .pii-item:last-child {
               border-bottom: none;
           }


           .pii-type {
               font-weight: 600;
               margin-bottom: 5px;
               display: flex;
               align-items: center;
           }


           .pii-type-label {
               background-color: #e8f0fe;
               color: var(--primary-dark);
               padding: 3px 8px;
               border-radius: 4px;
               margin-right: 10px;
               font-size: 12px;
           }


           .pii-type-ssn .pii-type-label {
               background-color: #ffebee;
               color: var(--danger);
           }


           .pii-type-credit .pii-type-label {
               background-color: #fff8e1;
               color: #ff8f00;
           }


           .pii-values {
               background-color: #f5f5f5;
               padding: 8px 12px;
               border-radius: 4px;
               font-family: monospace;
               font-size: 14px;
               color: var(--text-dark);
               word-break: break-all;
           }


           .footer {
               text-align: center;
               margin-top: 40px;
               color: var(--text-light);
               font-size: 14px;
           }
          
           <!--if not PII is found, no results message-->
           .no-results {
               text-align: center;
               background: white;
               padding: 40px;
               border-radius: 8px;
               box-shadow: var(--card-shadow);
           }
          
           <!--interactive collapsible toggle buttons to expand on findings-->
           .collapsible {
               background-color: white;
               cursor: pointer;
               width: 100%;
               border: none;
               text-align: left;
               outline: none;
               font-size: 18px;
               font-weight: bold;
               display: flex;
               justify-content: space-between;
               align-items: center;
           }


           .content {
               max-height: 0;
               overflow: hidden;
               transition: max-height 0.2s ease-out;
           }


           .toggle-icon:after {
               content: '\\002B';
               font-weight: bold;
               float: right;
               margin-left: 5px;
               font-size: 22px;
           }


           .active .toggle-icon:after {
               content: '\\2212';
           }
       </style>
   </head>
   <body>
       <div class="header">
           <h1>PII Detection Report</h1>
          
           <!--displays time of the scan and how many files found with PII-->
           <div class="summary">
               <p>Scan completed on {{ scan_time }}</p>
               <p>Found {{ results|length }} files containing potential PII</p>
           </div>
       </div>




       <!--checks for risk level based on priority numbers as low, high, or medium-->
       {% if results %}
           {% for item in results %}
               {% set risk_level = "low" %}
               {% if item.highest_priority >= 6 %}
                   {% set risk_level = "high" %}
               {% elif item.highest_priority >= 2 %}
                   {% set risk_level = "medium" %}
               {% else %}
                   {% set risk_level = "low" %}
               {% endif %}
       <!--renders the file card for each file found + the color of risk with file name, path, and risk badge-->
               <div class="file-card {% if risk_level == 'high' %}high-risk{% elif risk_level == 'medium' %}medium-risk{% endif %}">
                   <div class="file-header">
                       <div class="file-title">
                           <div class="collapsible">
                               <span class="file-name">{{ item.file_name }}</span>
                               <span class="toggle-icon"></span>
                           </div>
                           <div class="file-path">{{ item.dir_name }}</div>
                       </div>
                       <div class="risk-badge {{ risk_level }}">
                           {{ risk_level|upper }} RISK
                       </div>
                   </div>
       <!--show each expanded PII inside its own file card-->
                   <div class="content">
                       <ul class="pii-list">
                           {% for label, matches in item.matches %}
                               <li class="pii-item pii-type-{{ label|lower|replace(' ', '-') }}">
                                   <div class="pii-type">
                                       <span class="pii-type-label">{{ label }}</span>
                                       <span>{{ matches|length }} found</span>
                                   </div>
                                   <div class="pii-values">{{ matches|join('</br>') }}</div>
                               </li>
                           {% endfor %}
                       </ul>
                   </div>
               </div>
           {% endfor %}
       {% else %}
       <!--if there were no results for PII-->
           <div class="no-results">
               <h2>No PII Found</h2>
               <p>Your scan did not detect any personally identifiable information in the scanned files.</p>
           </div>
       {% endif %}


       <!--footer for project name and copyright-->
       <div class="footer">
           <p>PII Scanner Tool Final Project &copy; 2025</p>
       </div>


       <!--JavaScript toggle panel for opening and closing contents of file card-->
       <script>
           document.addEventListener('DOMContentLoaded', function() {
               var coll = document.getElementsByClassName("collapsible");
               for (var i = 0; i < coll.length; i++) {
                   coll[i].addEventListener("click", function() {
                       this.classList.toggle("active");
                       var content = this.parentElement.parentElement.nextElementSibling;
                       if (content.style.maxHeight) {
                           content.style.maxHeight = null;
                       } else {
                           content.style.maxHeight = content.scrollHeight + "px";
                       }
                   });


                   <!--Open the first item by default, other ones are collapsed-->
                   if (i < 1) {
                       coll[i].click();
                   }
               }
           });
       </script>
   </body>
   </html>
   """)


   output = template.render(results=processed_results, scan_time=scan_time) #renders the HTML file through Jinja2
   with open(REPORT_PATH, "w") as f: #writes the HTML output at the specific path
       f.write(output)
   webbrowser.open("file://" + REPORT_PATH) #opens the report locally on a user's default web browser


# main
if __name__ == "__main__": #runs when the script/code is being executed
   pii_results = scan_files() #calls for the main scanning function (walks through directories, reads it, looks for regex matches, returns into the list)
   if pii_results: #if pii_results exists (not empty), we move onto generating it
       generate_report(pii_results) #generates HTML report
       print(f"Report generated at: {REPORT_PATH}") #prints in the terminal
   else: #skips the report if it doesnt exist
       print("No PII found.")


