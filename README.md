{\rtf1\ansi\ansicpg1252\cocoartf2822
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;\red0\green0\blue0;\red0\green0\blue0;}
{\*\expandedcolortbl;;\cspthree\c0\c0\c0;\cssrgb\c0\c0\c0;}
\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\pard\tx560\tx1120\tx1680\tx2240\tx2800\tx3360\tx3920\tx4480\tx5040\tx5600\tx6160\tx6720\pardirnatural\partightenfactor0

\f0\fs24 \cf2 \
\pard\tx560\tx1120\tx1680\tx2240\tx2800\tx3360\tx3920\tx4480\tx5040\tx5600\tx6160\tx6720\pardirnatural\partightenfactor0
\cf2 \uc0\u8237  This project is a Python-based Personally Identifiable Information scanner. It is designed to scan\uc0\u8236 \
\uc0\u8237  users' Desktop, Downloads, and Documents for common file types (.txt, .docx, and .pdf) to\uc0\u8236 \
\uc0\u8237  extract text content and identify potential PII instances using regular expressions. Detected PII\uc0\u8236 \
\uc0\u8237  is then compiled into a user-friendly HTML report (locally, for security purposes) that categorizes\uc0\u8236 \
\uc0\u8237  findings by file, highlights risk levels based on the PII type, and allows for easy review. This\uc0\u8236 \
\uc0\u8237  project was made to create a tool to help users identify potential data privacy risks and PII files\uc0\u8236 \
\uc0\u8237  on their local machines for further investigation or deletion.\uc0\u8236 \
\
\
\pard\pardeftab720\partightenfactor0
\cf0 \expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec3 1. Make sure Python 3.x+ is installed. Check by doing \'91python3 --version\'92 in terminal. If not, then install Python on the computer. Update Python for best results.\
\
2. The following Python libraries should be installed:\
\
```pip install python-docx PyPDF2 Jinja2```\
\
3. Download the Python script (dlp_scanner.py). Run the script from your terminal:\
\
```python pii_scanner.py```\
\
4. Let it run through fully; you may encounter some errors with the PyPDF2 module. This is expected.\
}