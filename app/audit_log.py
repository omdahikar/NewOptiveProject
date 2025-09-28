import csv
import os
import re
from datetime import datetime
from . import config

LOG_FILE = config.PROJECT_ROOT / "redaction_log.csv"
LOG_HEADERS = ["timestamp", "file_name", "masked_original", "redacted_to", "reason"]

def _mask_sensitive_text(text: str) -> str:
    """Masks sensitive text for secure logging, showing only the first and last characters."""
    text = str(text)
    length = len(text)
    
    # Special handling for emails to make logs more readable
    if re.match(r'[^@]+@[^@]+\.[^@]+', text):
        parts = text.split('@')
        user = parts[0]
        domain = parts[1]
        masked_user = f"{user[0]}...{user[-1]}" if len(user) > 2 else f"{user[0]}..."
        masked_domain = f"{domain[0]}...{domain.split('.')[-1]}" if '.' in domain and len(domain) > 2 else f"{domain[0]}..."
        return f"{masked_user}@{masked_domain}"

    # General masking for other text
    if length <= 2:
        return "*" * length
    elif length <= 5:
        return f"{text[0]}{'*' * (length - 2)}{text[-1]}"
    else:
        return f"{text[:2]}...{text[-2:]}"

def initialize_log():
    """Creates the log file with headers if it doesn't exist."""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(LOG_HEADERS)

def log_redaction(file_name, original, redacted, reason):
    """Appends a redaction event to the CSV log with masked original text."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Sanitize and mask the original text for secure logging
    sanitized_original = ' '.join(str(original).splitlines())
    masked_original = _mask_sensitive_text(sanitized_original)
    
    with open(LOG_FILE, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, file_name, masked_original, redacted, reason])