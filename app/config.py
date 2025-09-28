'''
import pathlib
import re

# --- Core Paths ---
PROJECT_ROOT = pathlib.Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
RAW_FILES_DIR = DATA_DIR / "raw_files"
PROCESSED_FILES_DIR = DATA_DIR / "processed_files"
OUTPUT_REPORTS_DIR = DATA_DIR / "output_reports"
# --- NEW: Path to custom data for advanced detection ---
CUSTOM_DATA_DIR = PROJECT_ROOT / "custom_data"
LOGO_DIR = CUSTOM_DATA_DIR / "logos"

# --- Tesseract Configuration ---
TESSERACT_CMD_PATH = "C:/Program Files/Tesseract-OCR/tesseract.exe"

# --- Comprehensive PII & Sensitive Data Rules ---
PII_REDACTION_RULES = {
    re.compile(r'\b(root|admin)@([a-zA-Z0-9\-_]+\-[a-zA-Z0-9\-_]+)\b'): "<user>@<hostname>",
    # NEW: Catches server hostnames like 'corp-dc01' or 'CORP-FW-01'
    re.compile(r'\b([a-zA-Z0-9\-_]+\-[a-zA-Z0-9\-_]+(\-[0-9]{1,2})?)\b'): "<hostname>",
    
    # Catches template placeholders like '[Organization Name]'
    re.compile(r'\[\s*(?:Company|Organization|Client|Customer|Your)\s*Name\s*\]', re.IGNORECASE): "<organization>",
    
    # Existing powerful rules
    
    re.compile(r'(password|pass|passwd|pwd|secret|token|apikey)[\s:=]+[^\s]+', re.IGNORECASE): "<credential>",
    re.compile(r'\b(ssh-rsa AAAA[0-9A-Za-z+/]+[=]{0,3}( [^@]+@[^@]+)?)\b'): "<ssh_key>",
    re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'): "<ip>",
    re.compile(r'\b([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})\b'): "<mac_address>",
    re.compile(r'\b([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b'): "<hostname>",
    re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'): "<email>",
    re.compile(r'\b(?:\+91[\-\s]?)?[6789]\d{9}\b'): "<mobile no>",
    re.compile(r'\b\d{3}-\d{2}-\d{4}\b'): "<ssn>",
    re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b'): "<bank code>",
    re.compile(r'\b\d{9,18}\b'): "<account no>",
    re.compile(r'\b[a-zA-Z0-9.\-_]+@[a-zA-Z0-9.\-_]+\b'): "<upi id>",
    re.compile(r'\b(?:\d[ -]*?){13,16}\b'): "<credit_card>",
    re.compile(r'(?<!\d)\d{6}(?!\d)'): "<6-digit code>",
}

# NEW: Final, expanded keyword list
SENSITIVE_KEYWORDS = [
    "Optiv", "ClientCorp", "Project Titan", "Vengadamangalam", 
    "Kavitha", "SBI", "root", "admin", "Heather Trujillo", 
    "Chris C. Christopherson", "Arbortext"
]
KEYWORD_REPLACEMENT_TAG = "<name>"

# --- ADVANCED AI (NER) CONFIGURATION ---
NER_REDACTION_RULES = {
    "PERSON": "<name>",
    "ORG": "<organization>",
    "GPE": "<location>",
    "LOC": "<location>",
}

# --- NEW: CONTEXT-AWARE RULES ---
# Defines patterns where the text FOLLOWING a trigger phrase is sensitive.
# The `TARGET_TYPE` corresponds to a spaCy token type. 'NUM' is for numbers.
CONTEXTUAL_RULES = [
    {"trigger_phrase": "Salary:", "TARGET_TYPE": "NUM", "redaction_tag": "<salary_amount>"},
    {"trigger_phrase": "Account Balance:", "TARGET_TYPE": "NUM", "redaction_tag": "<financial_amount>"},
    {"trigger_phrase": "Transaction ID is", "TARGET_TYPE": "NUM", "redaction_tag": "<transaction_id>"},
]

# --- Parallel Processing ---
MAX_WORKERS = 4
'''
import pathlib
import re

# --- Core Paths ---
PROJECT_ROOT = pathlib.Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
RAW_FILES_DIR = DATA_DIR / "raw_files"
PROCESSED_FILES_DIR = DATA_DIR / "processed_files"
OUTPUT_REPORTS_DIR = DATA_DIR / "output_reports"

# --- NEW: Path to custom data for advanced detection ---
CUSTOM_DATA_DIR = PROJECT_ROOT / "custom_data"
LOGO_DIR = CUSTOM_DATA_DIR / "logos"
WHITELIST_FILE = CUSTOM_DATA_DIR / "whitelist.txt"  # Add whitelist support

# --- Tesseract Configuration ---
TESSERACT_CMD_PATH = "C:/Program Files/Tesseract-OCR/tesseract.exe"

# --- Whitelisting Rules (to prevent over-redaction) ---
# Common words that should NOT be redacted even if they match patterns
WHITELIST_KEYWORDS = {
    "the", "and", "for", "with", "from", "this", "that", "these", "those",
    "have", "has", "had", "will", "would", "could", "should", "may", "might",
    "can", "could", "must", "shall", "being", "been", "were", "was", "are", "is",
    "data", "file", "document", "report", "analysis", "system", "process",
    "method", "approach", "solution", "problem", "issue", "error", "warning",
    "info", "information", "details", "summary", "overview", "introduction",
    "conclusion", "reference", "example", "sample", "test", "demo", "template"
}

# --- Enhanced PII & Sensitive Data Rules with Priority ---
# Higher priority rules are processed first
PII_REDACTION_RULES = {
    # Priority 1: Most specific patterns (process these first)
    
    # Indian Aadhaar number (12 digits, often in groups of 4)
    re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'): "<aadhaar>",
    
    # Indian PAN card
    re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'): "<pan>",
    
    # Indian Passport
    re.compile(r'\b[A-Z][0-9]{7}\b'): "<passport>",
    
    # Indian Driving License (varies by state)
    re.compile(r'\b[A-Z]{2}[0-9]{2}[\s-]?[0-9]{11}\b'): "<driving_license>",
    
    # Bank Account Numbers (Indian format)
    re.compile(r'\b\d{9,18}\b'): "<account_no>",
    
    # IFSC Code
    re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b'): "<ifsc_code>",
    
    # Credit/Debit Card Numbers
    re.compile(r'\b(?:\d[\s-]*?){13,19}\b'): "<card_number>",
    
    # CVV
    re.compile(r'\b(?:CVV|CVC|CV2|CID)[\s:]*\d{3,4}\b', re.IGNORECASE): "<cvv>",
    
    # Priority 2: Authentication & Security patterns
    
    # API Keys and Tokens (various formats)
    re.compile(r'\b(?:api[_-]?key|token|bearer|auth[_-]?key)[\s:=]+[\w\-\.]+\b', re.IGNORECASE): "<api_key>",
    
    # Passwords and secrets (improved pattern)
    re.compile(r'(?:password|passwd|pwd|pass|secret|pin|passcode)[\s:=]+[^\s]+', re.IGNORECASE): "<password>",
    
    # SSH Keys
    re.compile(r'(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp256)\s+[A-Za-z0-9+/=]+', re.IGNORECASE): "<ssh_key>",
    
    # Private Keys
    re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----'): "<private_key>",
    
    # Priority 3: Contact Information
    
    # Email addresses (improved to handle more formats)
    re.compile(r'\b[a-zA-Z0-9][a-zA-Z0-9._%+-]{0,63}@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'): "<email>",
    
    # Indian Mobile Numbers (with country code variations)
    re.compile(r'(?:\+91[\s-]?|91[\s-]?|0)?[6-9]\d{9}\b'): "<mobile>",
    
    # Indian Landline Numbers
    re.compile(r'(?:\+91[\s-]?|0)?(?:[1-9]\d{1,4})[\s-]?\d{6,8}\b'): "<landline>",
    
    # International Phone Numbers
    re.compile(r'(?:\+\d{1,3}[\s-]?)?\(?\d{1,4}\)?[\s-]?\d{1,4}[\s-]?\d{4,10}\b'): "<phone>",
    
    # Priority 4: Network & System Information
    
    # IP Addresses (IPv4)
    re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'): "<ipv4>",
    
    # IP Addresses (IPv6)
    re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'): "<ipv6>",
    
    # MAC Addresses
    re.compile(r'\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b', re.IGNORECASE): "<mac_address>",
    
    # --- NEW: More generic pattern for internal hostnames (e.g., corp-db-cluster-01) ---
    re.compile(r'\b([a-z0-9]+-){1,4}[a-z0-9-]+\b', re.IGNORECASE): "<hostname>",

    # URLs with potential sensitive parameters
    re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+(?:\?[^\s<>"{}|\\^`\[\]]+)?'): "<url>",
    
    # Server/Host names (improved pattern)
    re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b'): "<hostname>",
    
    # Priority 5: Financial Information
    
    # UPI IDs
    re.compile(r'\b[a-zA-Z0-9._-]+@[a-zA-Z]{3,}\b'): "<upi_id>",
    
    # Amount patterns (Indian currency)
    re.compile(r'(?:₹|Rs\.?|INR)[\s]?\d+(?:,\d{3})*(?:\.\d{2})?', re.IGNORECASE): "<amount>",
    
    # Priority 6: General Patterns
    
    # Social Security Numbers (US)
    re.compile(r'\b\d{3}-\d{2}-\d{4}\b'): "<ssn>",
    
    # Date of Birth patterns
    re.compile(r'\b(?:DOB|Date of Birth)[\s:]+\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b', re.IGNORECASE): "<dob>",
    
    # Employee/Customer IDs
    re.compile(r'\b(?:EMP|CUST|ID|REF)[\s-]?\d{4,10}\b', re.IGNORECASE): "<id>",
    
    # Generic 6-digit codes (OTP, PIN, etc.)
    re.compile(r'\b(?<![\d-])\d{6}(?![\d-])\b'): "<code>",
}

# --- Enhanced Sensitive Keywords with Categories ---
SENSITIVE_KEYWORDS = {
    # Company/Organization Names
    "company_names": [
        "Optiv", "ClientCorp", "Project Titan", "Arbortext",
        "Accenture", "Infosys", "TCS", "Wipro", "Cognizant",
        "Microsoft", "Google", "Amazon", "Meta", "Apple"
    ],
    
    # Person Names (add more as needed)
    "person_names": [
        "Kavitha", "Heather Trujillo", "Chris C. Christopherson",
        "John Doe", "Jane Smith"
    ],
    
    # Location Names
    "locations": [
        "Vengadamangalam", "Chengalpattu", "Chennai", "Mumbai",
        "Bangalore", "Hyderabad", "Delhi", "Kolkata"
    ],
    
    # Financial Institutions
    "banks": [
        "SBI", "HDFC", "ICICI", "Axis Bank", "PNB", "Bank of Baroda",
        "Canara Bank", "Union Bank", "IDBI", "Kotak Mahindra"
    ],
    
    # Technical/Admin Terms
    "technical": [
        "root", "admin", "administrator", "superuser", "sa",
        "postgres", "mysql", "oracle", "mongodb"
    ],
    
    # Project/Product Names
    "projects": [
        "Project Alpha", "Project Beta", "Confidential Project",
        "Internal System", "Production Database"
    ],
    
    # Medical/Health Terms
    "medical": [
        "diagnosis", "prescription", "medical record", "patient",
        "treatment", "medication", "health insurance"
    ]
}

# Flatten the keywords dictionary for backward compatibility
FLAT_SENSITIVE_KEYWORDS = []
for category, keywords in SENSITIVE_KEYWORDS.items():
    FLAT_SENSITIVE_KEYWORDS.extend(keywords)

KEYWORD_REPLACEMENT_TAG = "<redacted>"

# --- Enhanced NER Configuration ---
NER_REDACTION_RULES = {
    "PERSON": "<person>",
    "ORG": "<organization>",
    "GPE": "<location>",  # Geopolitical entities
    "LOC": "<location>",   # Locations
    "DATE": "<date>",      # Dates that might be sensitive
    "MONEY": "<amount>",   # Monetary values
    "CARDINAL": None,      # Numbers (handle with context)
    "FAC": "<facility>",   # Facilities
    "PRODUCT": "<product>", # Products
}

# --- Enhanced Context-Aware Rules ---
CONTEXTUAL_RULES = [
    # --- NEW RULES FOR FIREWALL / INFRASTRUCTURE ---
    {"trigger_phrase": "Source:", "TARGET_TYPE": "TEXT_ON_LINE", "redaction_tag": "<source>"},
    {"trigger_phrase": "Destination:", "TARGET_TYPE": "TEXT_ON_LINE", "redaction_tag": "<destination>"},
    {"trigger_phrase": "Install On:", "TARGET_TYPE": "TEXT_ON_LINE", "redaction_tag": "<install_target>"},
    
    
    
    # Financial contexts
    {"trigger_phrase": "Salary:", "TARGET_TYPE": "NUM", "redaction_tag": "<salary>"},
    {"trigger_phrase": "Account Balance:", "TARGET_TYPE": "NUM", "redaction_tag": "<balance>"},
    {"trigger_phrase": "Transaction ID", "TARGET_TYPE": "NUM", "redaction_tag": "<transaction_id>"},
    {"trigger_phrase": "Invoice No", "TARGET_TYPE": "NUM", "redaction_tag": "<invoice_no>"},
    {"trigger_phrase": "Order ID", "TARGET_TYPE": "NUM", "redaction_tag": "<order_id>"},
    {"trigger_phrase": "Reference No", "TARGET_TYPE": "NUM", "redaction_tag": "<reference_no>"},
    
    # Personal Information contexts
    {"trigger_phrase": "Age:", "TARGET_TYPE": "NUM", "redaction_tag": "<age>"},
    {"trigger_phrase": "Employee ID:", "TARGET_TYPE": "NUM", "redaction_tag": "<employee_id>"},
    {"trigger_phrase": "Customer ID:", "TARGET_TYPE": "NUM", "redaction_tag": "<customer_id>"},
    {"trigger_phrase": "Policy No", "TARGET_TYPE": "NUM", "redaction_tag": "<policy_no>"},
    
    # Authentication contexts
    {"trigger_phrase": "PIN:", "TARGET_TYPE": "NUM", "redaction_tag": "<pin>"},
    {"trigger_phrase": "OTP:", "TARGET_TYPE": "NUM", "redaction_tag": "<otp>"},
    {"trigger_phrase": "Verification Code:", "TARGET_TYPE": "NUM", "redaction_tag": "<verification_code>"},

]

# --- Confidence Thresholds ---
OCR_CONFIDENCE_THRESHOLD = 40  # Minimum OCR confidence for text extraction
NER_CONFIDENCE_THRESHOLD = 0.85  # Minimum confidence for NER entities

# --- Visual Detection Parameters ---
SIGNATURE_DETECTION_PARAMS = {
    "min_area": 500,
    "max_area": 150000,
    "min_aspect_ratio": 1.2,
    "max_aspect_ratio": 15.0,
    "threshold_value": 120
}

FACE_DETECTION_PARAMS = {
    "scale_factor": 1.1,
    "min_neighbors": 4,
    "blur_kernel_size": (99, 99),
    "blur_sigma": 30
}

# --- Parallel Processing ---
MAX_WORKERS = 4

# --- Logging Configuration ---
ENABLE_DETAILED_LOGGING = True
LOG_REDACTION_REASONS = True