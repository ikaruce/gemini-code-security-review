"""Constants for Gemini Code Security Review."""

# Default Gemini model for security analysis (most capable)
DEFAULT_GEMINI_MODEL = "gemini-2.5-pro"

# Fallback model for false-positive filtering (faster, cheaper)
DEFAULT_FILTERING_MODEL = "gemini-2.0-flash"

# Local LLM defaults
DEFAULT_LOCAL_LLM_MODEL = "llama3.2"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_LMSTUDIO_BASE_URL = "http://localhost:1234"

# Timeouts
DEFAULT_TIMEOUT_SECONDS = 120
SUBPROCESS_TIMEOUT = 20 * 60  # 20 minutes in seconds
DEFAULT_MAX_RETRIES = 3

# Rate limit backoff
RATE_LIMIT_BACKOFF_MAX = 60  # seconds

# Prompt/token limits
PROMPT_TOKEN_LIMIT = 8192

# Exit codes
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_CONFIGURATION_ERROR = 2
