import json
import subprocess
from cert_conversion import transform_to_vince
import sys

def execute_vince_post(data, api_url, file_path=None):
    """
    Execute POST request to VINCE API
    
    Args:
        data: Dictionary containing form data
        api_url: Target API endpoint URL
        file_path: Optional path to file attachment
    
    Returns:
        subprocess.CompletedProcess object with response
    """
    curl_command = ['curl', '-X', 'POST', api_url]
    
    for key, value in data.items():
        if key == 'user_file' and not value:
            continue
            
        if isinstance(value, bool):
            value = str(value)
        elif value is None:
            value = ""
        else:
            value = str(value)
        
        curl_command.extend(['-F', f'{key}={value}'])
    
    if file_path:
        curl_command.extend(['-F', f'user_file=@{file_path}'])
    
    # Execute the curl command
    result = subprocess.run(curl_command, capture_output=True, text=True)
    
    return result

def main():
    json_file = "/PATH/TO/JSON-FILE.json"
    api_url = "https://bigvince-devtest-kb.testdit.org/vuls/api/vulreport/"
    file_path = None
    
    try:
        with open(json_file, 'r') as f:
            ai_report = json.load(f)
        
        vince_data = transform_to_vince(ai_report)
        
        result = execute_vince_post(vince_data, api_url, file_path)
        
        # results
        print("STATUS CODE:", result.returncode)
        print("\nRESPONSE:")
        print(result.stdout)
        
        if result.stderr:
            print("\nERRORS:")
            print(result.stderr)
            
    except FileNotFoundError:
        print(f"Error: File '{json_file}' not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in '{json_file}': {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()