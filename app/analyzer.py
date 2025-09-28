import google.generativeai as genai
import os
import json
import pathlib
import time
import PIL.Image

def get_file_type(filename: str) -> str:
    """Gets a user-friendly file type from the file extension."""
    suffix_map = {
        '.pdf': 'PDF Document',
        '.docx': 'Word Document',
        '.pptx': 'PowerPoint Presentation',
        '.xlsx': 'Excel Spreadsheet',
        '.csv': 'CSV Data File',
        '.png': 'PNG Image',
        '.jpg': 'JPEG Image',
        '.jpeg': 'JPEG Image',
        '.gif': 'GIF Image',
        '.bmp': 'BMP Image',
        '.webp': 'WebP Image',
        '.txt': 'Text File',
    }
    suffix = pathlib.Path(filename).suffix.lower()
    return suffix_map.get(suffix, "Unknown File Type")

def test_api_connection():
    """Test API connection and list available models"""
    try:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            print("❌ GEMINI_API_KEY environment variable is not set")
            return False
        
        genai.configure(api_key=api_key)
        
        print("Testing API connection...")
        models = genai.list_models()
        available_models = []
        for model in models:
            available_models.append(model.name)
            print(f"  - {model.name}")
            if hasattr(model, 'supported_generation_methods'):
                methods = getattr(model, 'supported_generation_methods', [])
                if methods:
                    print(f"    Methods: {methods}")
        
        print(f"✅ Found {len(available_models)} available models")
        return True
        
    except Exception as e:
        print(f"❌ API connection test failed: {e}")
        return False

def get_working_model():
    """Get a working model for the current API setup"""
    model_priority = [
        # Latest models first
        'gemini-1.5-flash-latest',
        'gemini-1.5-flash',
        'gemini-1.5-pro-latest', 
        'gemini-1.5-pro',
        # Specific versions
        'gemini-1.5-flash-002',
        'gemini-1.5-flash-001',
        'gemini-1.5-pro-002',
        'gemini-1.5-pro-001',
        # With models/ prefix
        'models/gemini-1.5-flash',
        'models/gemini-1.5-pro',
        # Fallback to newer models
        'gemini-2.0-flash',
        'gemini-2.5-flash',
    ]
    
    for model_name in model_priority:
        try:
            model = genai.GenerativeModel(model_name)
            # Test with a simple generation to ensure it works
            test_response = model.generate_content("Test")
            if test_response:
                print(f"   -> Using model: {model_name}")
                return model, model_name
        except Exception as e:
            continue
    
    raise ValueError("No working model found. Please check your API key and available models.")

def generate_insights(text_content: str, original_filename: str, cleansed_filepath: str) -> dict:
    """
    Generates a professional-grade security analysis using a multimodal AI (Gemini Vision)
    for images and a text model for other documents.
    """
    file_type = get_file_type(original_filename)
    is_image = pathlib.Path(cleansed_filepath).suffix.lower() in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp']

    if not text_content or text_content.strip() == "No text content found.":
        if not is_image:
            return {
                "document_summary": "A file that is blank or contains no discernible text content.",
                "key_security_findings": [
                    "The submitted file lacks content, indicating a potential data integrity issue or a process gap in evidence collection."
                ],
                "source_file_name": original_filename,
                "source_file_type": file_type
            }
        
    try:
        # Configure API
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable is not set")
        
        genai.configure(api_key=api_key)

        # Get working model
        model, model_name = get_working_model()
        
        if is_image:
            # Handle image files
            try:
                image_input = PIL.Image.open(cleansed_filepath)
                
                # Convert RGBA to RGB if necessary (for compatibility)
                if image_input.mode == 'RGBA':
                    rgb_image = PIL.Image.new('RGB', image_input.size, (255, 255, 255))
                    rgb_image.paste(image_input, mask=image_input.split()[3] if len(image_input.split()) > 3 else None)
                    image_input = rgb_image
                    
            except Exception as e:
                return {
                    "error": f"Failed to open image file: {str(e)}",
                    "source_file_name": original_filename,
                    "source_file_type": file_type
                }
            
            # Enhanced vision prompt for comprehensive image analysis
            vision_prompt = f"""You are an expert security analyst conducting a thorough assessment of this image from file: {original_filename}

ANALYSIS FRAMEWORK:
Examine this image systematically and provide detailed insights covering these areas:

1. SCENE DESCRIPTION:
   - Physical environment and setting (indoor/outdoor, type of facility, location characteristics)
   - Visible people: count, roles, activities, behavior patterns
   - Objects and equipment present
   - Time indicators (lighting, shadows, digital displays)
   - Spatial layout and architectural features

2. SECURITY ASSESSMENT:
   - Physical security controls: access control systems, cameras, locks, barriers, lighting
   - Personnel security: badges, uniforms, positioning, procedures being followed
   - Information security: visible screens, documents, whiteboards, signage
   - Environmental security: emergency exits, safety equipment, hazard areas
   - Perimeter security: fencing, gates, entry points, visitor controls

3. ACTIVITIES & BEHAVIORS:
   - What specific actions are people performing?
   - Are proper security procedures being followed?
   - Any signs of unauthorized access or suspicious behavior?
   - Compliance with visible policies or procedures

4. VULNERABILITIES & RISKS:
   - Security gaps or weaknesses observed
   - Policy violations or non-compliance
   - Potential attack vectors or security risks
   - Areas lacking adequate protection

5. REDACTED CONTENT (if present):
   - Note any blacked-out or redacted areas
   - Explain what these redactions likely protect (PII, sensitive info, etc.)

IMPORTANT CONTEXT:
- Black rectangles or blacked-out areas are INTENTIONAL REDACTIONS for privacy/security
- Focus analysis on visible, non-redacted content
- Be specific and actionable in your findings
- Avoid generic security advice - focus on what you actually observe

Provide your analysis in this exact JSON format:
{{
  "document_summary": "Detailed description of the scene, people, activities, and environment observed in the image",
  "key_security_findings": [
    "List specific security observations",
    "Include both positive security measures and vulnerabilities found", 
    "Note any redacted areas and their likely purpose",
    "Be specific about what you observe, not generic advice"
  ],
  "environment_type": "office/industrial/retail/public/residential/other",
  "people_count": "number of people visible",
  "redacted_content_noted": true/false,
  "security_controls_observed": ["list specific security measures seen"],
  "potential_vulnerabilities": ["list specific risks or gaps observed"]
}}

Be thorough, specific, and professional. Focus only on what is actually visible in the image."""

            api_input = [vision_prompt, image_input]
            
        else:
            # Enhanced text analysis prompt
            text_prompt = f"""You are a Principal Security Consultant conducting a comprehensive analysis of the document: '{original_filename}' ({file_type})

DOCUMENT CONTENT TO ANALYZE:
---
{text_content[:15000]}
---

ANALYSIS REQUIREMENTS:
Conduct a thorough security assessment covering these dimensions:

1. CONTENT CLASSIFICATION:
   - Type of document and its security relevance
   - Sensitivity level and data classification
   - Business context and operational purpose

2. SECURITY-RELEVANT FINDINGS:
   - Access controls, authentication mechanisms, authorization procedures
   - Data protection measures, encryption, privacy controls
   - Security policies, procedures, and compliance requirements
   - Network security, infrastructure protections, system configurations
   - Incident response, monitoring, and audit capabilities
   - Physical security measures and environmental controls

3. RISK ASSESSMENT:
   - Potential security vulnerabilities or weaknesses identified
   - Compliance gaps or policy violations
   - Data exposure risks or privacy concerns
   - Operational security risks

4. RECOMMENDATIONS:
   - Priority security improvements needed
   - Compliance actions required
   - Risk mitigation strategies

Provide your analysis in this exact JSON format:
{{
  "document_summary": "Professional executive summary of the document content, purpose, and security relevance",
  "key_security_findings": [
    "List specific security-related observations from the content",
    "Include both positive security measures and areas of concern",
    "Focus on actionable findings relevant to security assessment",
    "Be specific about what the document reveals about security posture"
  ],
  "document_type_classification": "policy/procedure/technical/audit/compliance/other",
  "sensitivity_assessment": "public/internal/confidential/restricted",
  "compliance_frameworks_referenced": ["list any mentioned standards or regulations"],
  "security_domains_covered": ["list relevant security areas addressed"],
  "priority_recommendations": ["list top 3-5 priority actions needed"]
}}

Be thorough, specific, and focus on security-relevant insights. Avoid generic advice - analyze what this specific document reveals."""

            api_input = [text_prompt]

        # Retry logic with exponential backoff
        max_retries = 3
        delay = 15
        
        for attempt in range(max_retries):
            try:
                response = model.generate_content(api_input)
                
                if not response or not response.text:
                    raise ValueError("Empty response from API")
                
                json_text = response.text.strip()
                
                # Extract JSON from response
                start_index = json_text.find('{')
                end_index = json_text.rfind('}') + 1
                
                if start_index != -1 and end_index > start_index:
                    clean_json = json_text[start_index:end_index]
                    analysis_data = json.loads(clean_json)
                    
                    # Add metadata
                    analysis_data["source_file_name"] = original_filename
                    analysis_data["source_file_type"] = file_type
                    analysis_data["model_used"] = model_name
                    analysis_data["analysis_timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Ensure required fields exist
                    if "document_summary" not in analysis_data:
                        analysis_data["document_summary"] = "Analysis completed but summary not provided"
                    if "key_security_findings" not in analysis_data:
                        analysis_data["key_security_findings"] = ["Analysis completed but no specific findings provided"]
                    
                    print(f"   -> ✅ Analysis successful for {original_filename}")
                    return analysis_data
                    
                else:
                    # If no JSON found, create structured response from raw text
                    return {
                        "document_summary": f"Analysis of {file_type}: " + (json_text[:300] if json_text else "No analysis available"),
                        "key_security_findings": [
                            "AI provided unstructured analysis - manual review recommended",
                            f"Raw response length: {len(json_text)} characters"
                        ],
                        "source_file_name": original_filename,
                        "source_file_type": file_type,
                        "model_used": model_name,
                        "raw_analysis": json_text[:2000] if json_text else None
                    }
                    
            except json.JSONDecodeError as e:
                print(f"   -> JSON parsing error for {original_filename}: {str(e)}")
                if attempt == max_retries - 1:
                    return {
                        "document_summary": "Analysis completed but JSON parsing failed",
                        "key_security_findings": [
                            f"Raw analysis available but not in expected format: {str(e)}"
                        ],
                        "source_file_name": original_filename,
                        "source_file_type": file_type,
                        "model_used": model_name,
                        "raw_response": response.text[:1000] if response and response.text else None
                    }
                    
            except Exception as e:
                error_str = str(e)
                
                # Handle specific errors
                if "429" in error_str or "quota" in error_str.lower() or "rate limit" in error_str.lower():
                    if attempt < max_retries - 1:
                        print(f"   -> Rate limit hit for {original_filename}. Waiting {delay}s. Retry {attempt + 1}/{max_retries}")
                        time.sleep(delay)
                        delay *= 2
                        continue
                        
                elif "api key" in error_str.lower() or "unauthorized" in error_str.lower():
                    print(f"   -> ❌ CRITICAL: API Key issue.")
                    return {
                        "error": "API Key issue - please verify your credentials",
                        "source_file_name": original_filename,
                        "source_file_type": file_type
                    }
                    
                elif attempt == max_retries - 1:
                    print(f"   -> ❌ Analysis failed for {original_filename}: {error_str}")
                    return {
                        "error": f"Analysis failed: {error_str}",
                        "source_file_name": original_filename,
                        "source_file_type": file_type
                    }
                else:
                    print(f"   -> Error on attempt {attempt + 1}: {error_str}. Retrying...")
                    time.sleep(5)
                    
    except Exception as e:
        error_details = f"Critical error during analysis of {original_filename}: {str(e)}"
        print(f"   -> ❌ {error_details}")
        return {
            "error": error_details,
            "source_file_name": original_filename,
            "source_file_type": file_type
        }
    
    return {
        "error": f"Analysis for {original_filename} failed after all retries",
        "source_file_name": original_filename,
        "source_file_type": file_type
    }