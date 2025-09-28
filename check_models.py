# check_models.py
import os
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

try:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("GEMINI_API_KEY not found in .env file.")
    else:
        genai.configure(api_key=api_key)
        print("--- Models available from your location ---")
        for m in genai.list_models():
            if 'generateContent' in m.supported_generation_methods:
                print(m.name)
        print("------------------------------------------")
except Exception as e:
    print(f"An error occurred: {e}")