"""OpenHands LLM client wrapper."""
from __future__ import annotations
import os
import json
from typing import Dict, Optional


def _strip_json_comments_safe(text: str) -> str:
    """Remove // and /* */ comments only when outside JSON strings."""
    out = []
    in_string = False
    escaped = False
    in_line_comment = False
    in_block_comment = False
    i = 0
    n = len(text)

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if ch in ("\n", "\r"):
                in_line_comment = False
                out.append(ch)
            i += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue

        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        # Outside strings
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue

        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue

        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def _escape_unescaped_control_chars_in_strings(text: str) -> str:
    """
    Escape raw control characters inside JSON strings.
    This repairs common LLM output issues like unescaped newlines/tabs in string values.
    """
    out = []
    in_string = False
    escaped = False

    for ch in text:
        if in_string:
            if escaped:
                out.append(ch)
                escaped = False
                continue

            if ch == "\\":
                out.append(ch)
                escaped = True
                continue

            if ch == '"':
                out.append(ch)
                in_string = False
                continue

            # Escape illegal raw control chars inside JSON string values
            if ch == "\n":
                out.append("\\n")
                continue
            if ch == "\r":
                out.append("\\r")
                continue
            if ch == "\t":
                out.append("\\t")
                continue
            if ord(ch) < 0x20:
                out.append(f"\\u{ord(ch):04x}")
                continue

            out.append(ch)
            continue

        out.append(ch)
        if ch == '"':
            in_string = True
            escaped = False

    return "".join(out)


class OpenHandsLLMClient:
    """Wrapper around OpenHands SDK LLM for JSON completions."""
    
    def __init__(self, model: str = None):
        """Initialize LLM client from environment variables.
        
        Args:
            model: Optional model override (takes priority over LLM_MODEL env var).
                   Example: 'ollama/qwen2.5:7b', 'vertex_ai/gemini-2.0-flash-001'
        """
        self.model = model or os.getenv("LLM_MODEL", "vertex_ai/gemini-2.0-flash-001")
        self.api_key = os.getenv("LLM_API_KEY", "")
        self.base_url = os.getenv("LLM_BASE_URL", "")
        self.timeout = int(os.getenv("LLM_TIMEOUT", "120"))
        self.num_retries = int(os.getenv("LLM_NUM_RETRIES", "2"))
        
        # Auto-set base_url for ollama models
        # Priority: LLM_BASE_URL > OLLAMA_API_BASE > OLLAMA_HOST > fallback localhost
        if self.model.startswith("ollama/") and not self.base_url:
            self.base_url = os.getenv("OLLAMA_API_BASE") or os.getenv("OLLAMA_HOST") or "http://localhost:11434"
            
        # Determine if this is a Vertex AI model
        is_vertex = self.model.startswith("vertex_ai/")
        
        # Map generic LLM_* vars to Vertex specific vars (only for Vertex models)
        vertex_project = os.getenv("LLM_PROJECT") if is_vertex else None
        vertex_location = os.getenv("LLM_LOCATION") if is_vertex else None
        
        if vertex_project:
            os.environ["VERTEX_PROJECT"] = vertex_project
        if vertex_location:
            os.environ["VERTEX_LOCATION"] = vertex_location
        
        # Initialize LiteLLM directly (OpenHands uses it internally)
        try:
            import litellm
            
            # Configure LiteLLM
            litellm.set_verbose = False
            
            # Store config for completion calls
            self.llm_kwargs = {
                "model": self.model,
                "timeout": self.timeout,
            }
            
            # Only pass Vertex credentials for Vertex AI models
            if is_vertex:
                if vertex_project:
                    self.llm_kwargs["vertex_project"] = vertex_project
                if vertex_location:
                    self.llm_kwargs["vertex_location"] = vertex_location
            
            if self.api_key:
                self.llm_kwargs["api_key"] = self.api_key
            
            # IMPORTANT:
            # Vertex AI models should not inherit Ollama/custom api_base values
            # from env vars (e.g., LLM_BASE_URL=http://...:11434), because LiteLLM
            # builds Vertex URLs differently and this breaks with errors like:
            # "Invalid port: '11434:generateContent'".
            if is_vertex:
                if self.base_url:
                    print("Note: ignoring LLM_BASE_URL/OLLAMA_* for vertex_ai model")
            elif self.base_url:
                self.llm_kwargs["api_base"] = self.base_url
            
            # Debug: log effective LLM configuration (helps validate LLM_BASE_URL usage)
            try:
                # Avoid leaking large secrets in logs by masking api_key if present
                logged_kwargs = dict(self.llm_kwargs)
                if "api_key" in logged_kwargs and logged_kwargs["api_key"]:
                    logged_kwargs["api_key"] = "<redacted>"
                print(f"LLM client config: {logged_kwargs}")
            except Exception:
                pass
        except ImportError as e:
            raise RuntimeError(
                "Failed to import litellm. "
                "Install with: pip install litellm"
            ) from e
    
    def completion_json(
        self,
        schema_name: str,
        system_prompt: str,
        user_prompt: str,
        max_retries: int = 2  # Increased from 1 to 2
    ) -> Dict:
        """
        Get JSON completion from LLM.
        
        Args:
            schema_name: Name of the expected schema (for logging)
            system_prompt: System message
            user_prompt: User message
            max_retries: Number of JSON repair attempts
        
        Returns:
            Parsed JSON dict
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        for attempt in range(max_retries + 1):
            try:
                # Call LiteLLM
                import litellm
                import time
                
                # Add delay between retries (exponential backoff)
                if attempt > 0:
                    delay = 2 ** attempt  # 2s, 4s, 8s...
                    print(f"  Waiting {delay}s before retry...")
                    time.sleep(delay)
                
                # Only log retry attempts, not every call
                pass  # Removed verbose kwargs logging

                response = litellm.completion(
                    messages=messages,
                    **self.llm_kwargs
                )

                # Extract content from response
                content = response.choices[0].message.content
                
                # Brief token count for monitoring
                usage = getattr(response, 'usage', None)
                if usage:
                    print(f"  ✓ LLM responded ({usage.completion_tokens} tokens)")

                # Debug: log empty responses
                if not content or content.strip() == "":
                    print(f"  Warning: Empty response from LLM (attempt {attempt + 1}/{max_retries + 1})")
                    if attempt < max_retries:
                        continue
                    else:
                        raise RuntimeError("LLM returned empty response after all retries")
                
                # Try to parse JSON with aggressive cleaning
                content = content.strip()
                content = content.replace("\ufeff", "").replace("\x00", "")

                # Prefer extracting JSON inside triple-backtick fences first
                try:
                    import re as _re
                    m = _re.search(r'```(?:json\s*)?(\{.*?\}|\[.*?\])```', content, _re.DOTALL | _re.IGNORECASE)
                    if m:
                        content = m.group(1).strip()
                    else:
                        # Remove markdown code fences as fallback
                        if content.startswith("```json"):
                            content = content[7:]
                        if content.startswith("```"):
                            content = content[3:]
                        if content.endswith("```"):
                            content = content[:-3]
                        content = content.strip()
                except Exception:
                    # On any regex error, fall back to naive fence removal
                    if content.startswith("```json"):
                        content = content[7:]
                    if content.startswith("```"):
                        content = content[3:]
                    if content.endswith("```"):
                        content = content[:-3]
                    content = content.strip()
                
                # Remove comments safely (outside strings only)
                content = _strip_json_comments_safe(content)
                
                # Try to extract JSON if embedded in text
                import re
                if not content.startswith('{') and not content.startswith('['):
                    # Try to find JSON object
                    match = re.search(r'(\{.*\}|\[.*\])', content, re.DOTALL)
                    if match:
                        content = match.group(1)
                
                # Remove trailing commas before closing braces/brackets
                content = re.sub(r',(\s*[}\]])', r'\1', content)
                
                # Repair invalid raw control chars inside string values
                content = _escape_unescaped_control_chars_in_strings(content)

                content = content.strip()
                
                # Pre-process: Handle common LLM "math in string" hallucination
                # Matches: "A" * 123 or 'A' * 123
                try:
                    def replace_math(match):
                        quote = match.group(1)
                        char = match.group(2)
                        times = int(match.group(3))
                        # Limit to reasonable size to prevent DoS (e.g. 20MB)
                        if times > 20 * 1024 * 1024: return match.group(0)
                        return f'{quote}{char * times}{quote}'
                    
                    content = re.sub(r'(["\'])(.)\1\s*\*\s*(\d+)', replace_math, content)
                except Exception:
                    pass  # If regex fails, just proceed to json.loads

                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    # Fallback: Try ast.literal_eval for Python-style dicts/lists
                    # This handles:
                    # - Single quotes: {'key': 'val'}
                    # - Trailing commas: [1, 2,]
                    # - Basic math: "A" * 10 (sometimes works if it's simple literal)
                    # - Concatenation: "A" + "B" (sometimes)
                    try:
                        import ast
                        # ast.literal_eval is safe (no arbitrary code execution)
                        # It can handle basic Python literals which often matches what LLMs hallucinate
                        evaluated = ast.literal_eval(content)
                        if isinstance(evaluated, (dict, list)):
                            return evaluated
                    except (ValueError, SyntaxError):
                        # If ast fails too, then we truly have invalid data
                        pass
                    
                    # Re-raise original error to trigger retry logic
                    # Re-raise original error to trigger retry logic
                    raise

            except json.JSONDecodeError as e:
                # Minimal error logging - show only error type and position
                error_msg = str(e).split(':')[0] if ':' in str(e) else str(e)
                print(f"  ⚠ JSON parse error: {error_msg[:60]}")
                
                if attempt < max_retries:
                    # Try to repair JSON
                    repair_prompt = (
                        f"The previous response was not valid JSON. "
                        f"Error: {str(e)}. "
                        f"Please provide ONLY valid JSON without any markdown formatting. "
                        f"Original response:\n{content}"
                    )
                    messages = [
                        {"role": "system", "content": "You must respond with valid JSON only."},
                        {"role": "user", "content": repair_prompt}
                    ]
                else:
                    raise RuntimeError(
                        f"Failed to parse JSON response after {max_retries + 1} attempts. "
                        f"Last error: {str(e)}\n"
                        f"Problematic content: {content[:500]}"
                    ) from e

    def completion_text(
        self,
        system_prompt: str,
        user_prompt: str,
        max_retries: int = 1,
        timeout_sec: Optional[int] = None,
    ) -> str:
        """
        Get plain-text completion from LLM (used for markdown summaries).

        Returns:
            Raw text content from assistant message.
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

        import litellm
        import time

        last_error = None
        for attempt in range(max_retries + 1):
            try:
                if attempt > 0:
                    delay = min(2 ** attempt, 8)
                    time.sleep(delay)

                kwargs = dict(self.llm_kwargs)
                if timeout_sec is not None and timeout_sec > 0:
                    kwargs["timeout"] = int(timeout_sec)

                response = litellm.completion(messages=messages, **kwargs)
                content = response.choices[0].message.content
                if content is None:
                    content = ""
                text = str(content).strip()
                if text:
                    return text
                last_error = "empty response"
            except Exception as e:
                last_error = str(e)

            if attempt >= max_retries:
                break

        raise RuntimeError(f"completion_text failed: {last_error}")
