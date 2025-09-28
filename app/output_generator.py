import json
import pathlib
from . import config

def save_analysis_report(analysis_data: dict, original_filename: str):
    """Saves the AI analysis data to a JSON file with robust error handling."""
    if "error" in analysis_data:
        print(f"   -> Skipping report for {original_filename} due to analysis error.")
        return

    try:
        report_filename = f"{pathlib.Path(original_filename).stem}_analysis.json"
        report_path = config.OUTPUT_REPORTS_DIR / report_filename
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(analysis_data, f, indent=4, ensure_ascii=False)
        
        print(f"   -> ✅ Successfully saved analysis report to {report_path.name}")

    except (IOError, PermissionError) as e:
        # This will catch errors if the directory doesn't exist or isn't writable
        print(f"   -> ❌ CRITICAL ERROR: Could not write report for {original_filename}. Reason: {e}")
    except Exception as e:
        # Catch any other unexpected errors during the file save process
        print(f"   -> ❌ An unexpected error occurred while saving the report for {original_filename}: {e}")