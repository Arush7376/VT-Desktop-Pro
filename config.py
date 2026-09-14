import os
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

VT_BASE_URL = os.getenv("VT_BASE_URL", "https://www.virustotal.com/api/v3")
HISTORY_FILE = os.getenv("HISTORY_FILE", "vt_history.json")


def get_api_key():
    """Retrieve the VirusTotal API key from environment variables or .env file."""
    api_key = os.getenv("VT_API_KEY", "").strip()
    return api_key if api_key else None


def validate_api_key(api_key: str) -> bool:
    """Validate that the provided API key is a non-empty string."""
    if not api_key or not isinstance(api_key, str):
        return False
    key = api_key.strip()
    return len(key) > 0


def save_api_key(api_key: str, env_filepath: str = ".env") -> bool:
    """Optionally persist the API key into a local .env file."""
    try:
        key = api_key.strip()
        lines = []
        key_found = False

        if os.path.exists(env_filepath):
            with open(env_filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()

        new_lines = []
        for line in lines:
            if line.strip().startswith("VT_API_KEY="):
                new_lines.append(f"VT_API_KEY={key}\n")
                key_found = True
            else:
                new_lines.append(line)

        if not key_found:
            if new_lines and not new_lines[-1].endswith("\n"):
                new_lines.append("\n")
            new_lines.append(f"VT_API_KEY={key}\n")

        with open(env_filepath, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        # Update current process environment
        os.environ["VT_API_KEY"] = key
        return True
    except Exception:
        return False
