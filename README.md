  
‭This project is a Python-based Personally Identifiable Information
scanner. It is designed to scan‬  
‭users\' Desktop, Downloads, and Documents for common file types (.txt,
.docx, and .pdf) to‬  
‭extract text content and identify potential PII instances using regular
expressions. Detected PII‬  
‭is then compiled into a user-friendly HTML report (locally, for security
purposes) that categorizes‬  
‭findings by file, highlights risk levels based on the PII type, and
allows for easy review. This‬  
‭project was made to create a tool to help users identify potential data
privacy risks and PII files‬  
‭on their local machines for further investigation or deletion.‬  
  
  
1. Make sure Python 3.x+ is installed. Check by doing 'python3
\--version' in terminal. If not, then install Python on the computer.
Update Python for best results.  
  
2. The following Python libraries should be installed:  
  
\`\`\`pip install python-docx PyPDF2 Jinja2\`\`\`  
  
3. Download the Python script (dlp_scanner.py). Run the script from your
terminal:  
  
\`\`\`python dlp_scanner.py\`\`\`  
  
4. Let it run through fully; you may encounter some errors with the
PyPDF2 module. This is expected.
