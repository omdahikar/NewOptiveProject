import os
import pathlib
import time
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

from app import config, cleanser, parser, analyzer, output_generator, audit_log, report_compiler

def main():
    """Main function to run the parallel file processing."""
    load_dotenv()
    audit_log.initialize_log()
    
    print(f"--- DEBUG: Is the key loaded? Key: {os.getenv('GEMINI_API_KEY')} ---")
    
    start_time = time.time()
    print("🚀 Initializing Automated File Cleansing and Analysis...")
    
    # Create all necessary directories
    for dir_path in [config.RAW_FILES_DIR, config.PROCESSED_FILES_DIR, config.OUTPUT_REPORTS_DIR]:
        dir_path.mkdir(exist_ok=True)
        
    files_to_process = [p for p in config.RAW_FILES_DIR.iterdir() if p.is_file()]
    if not files_to_process:
        print("No files found in 'data/raw_files'. Please add files to process.")
        return

    print(f"Found {len(files_to_process)} files. Starting parallel processing with {config.MAX_WORKERS} workers...")
    
    with ThreadPoolExecutor(max_workers=config.MAX_WORKERS) as executor:
        executor.map(process_single_file, files_to_process)
        
    end_time = time.time()
    print(f"\n✅ All individual files processed in {end_time - start_time:.2f} seconds.")
    
    # Final step: Compile all individual reports into one master report
    report_compiler.compile_final_report()

def process_single_file(filepath: pathlib.Path):
    """The complete, secure processing pipeline for a single file."""
    print(f"[Thread] Starting processing for: {filepath.name}")

    # --- STAGE 1: CLEANSING ---
    cleansed_filepath = config.PROCESSED_FILES_DIR / f"CLEANSED_{filepath.name}"
    
    try:
        file_ext = filepath.suffix.lower()
        if file_ext in cleanser.CLEANSER_DISPATCH:
            cleanse_func = cleanser.CLEANSER_DISPATCH[file_ext]
            cleanse_func(str(filepath), str(cleansed_filepath))
            print(f"   -> Cleansing successful for {filepath.name}")
        else:
            print(f"   -> No cleanser available for {file_ext}. Skipping.")
            return
    except Exception as e:
        print(f"   -> ❌ ERROR during cleansing of {filepath.name}: {e}")
        return

    # --- STAGE 2: SECURE AI ANALYSIS ---
    print(f"   -> Extracting text from CLEANSED file (if any): {cleansed_filepath.name}")
    text_content = parser.parse_text_from_file(str(cleansed_filepath))
    
    print(f"   -> Sending CLEANSED file to AI for deep analysis...")
    # Pass the cleansed file path to the new vision-enabled analyzer
    analysis_result = analyzer.generate_insights(text_content, filepath.name, str(cleansed_filepath))
    
    output_generator.save_analysis_report(analysis_result, filepath.name)
    
if __name__ == "__main__":
    main()