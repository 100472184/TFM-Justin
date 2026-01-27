"""OpenHands LLM client wrapper."""
from __future__ import annotations
import os
import json
from typing import Dict, Optional


class OpenHandsLLMClient:
    """Wrapper around OpenHands SDK LLM for JSON completions."""
    
    def __init__(self):
        """Initialize LLM client from environment variables."""
        self.model = os.getenv("LLM_MODEL", "ollama/llama3")
        self.api_key = os.getenv("LLM_API_KEY", "")
        self.base_url = os.getenv("LLM_BASE_URL", "")
        self.timeout = int(os.getenv("LLM_TIMEOUT", "120"))
        self.num_retries = int(os.getenv("LLM_NUM_RETRIES", "2"))
        
        # Auto-set base_url for ollama
        if self.model.startswith("ollama/") and not self.base_url:
            self.base_url = "http://localhost:11434"
        
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
            
            if self.api_key:
                self.llm_kwargs["api_key"] = self.api_key
            
            if self.base_url:
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
                
                # Debug: log the kwargs used for the call
                try:
                    kw_preview = dict(self.llm_kwargs)
                    if "api_key" in kw_preview and kw_preview["api_key"]:
                        kw_preview["api_key"] = "<redacted>"
                    print(f"  Calling LLM with kwargs: {kw_preview}")
                except Exception:
                    pass

                response = litellm.completion(
                    messages=messages,
                    **self.llm_kwargs
                )

                # Debug: log raw response object for troubleshooting JSON issues
                try:
                    print(f"  Raw LLM response: {repr(response)[:1000]}")
                except Exception:
                    pass
                
                # Extract content from response
                content = response.choices[0].message.content

                # Debug: log raw content preview
                try:
                    print(f"  Raw LLM content (first 1000 chars): {content[:1000]!s}")
                except Exception:
                    pass

                # Debug: log empty responses
                if not content or content.strip() == "":
                    print(f"  Warning: Empty response from LLM (attempt {attempt + 1}/{max_retries + 1})")
                    if attempt < max_retries:
                        continue
                    else:
                        raise RuntimeError("LLM returned empty response after all retries")
                
                # Try to parse JSON with aggressive cleaning
                content = content.strip()
                
                # Remove markdown code blocks
                if content.startswith("```json"):
                    content = content[7:]
                if content.startswith("```"):
                    content = content[3:]
                if content.endswith("```"):
                    content = content[:-3]
                content = content.strip()
                
                # Remove comments (// and /* */ style)
                import re
                # Remove single-line comments
                content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
                # Remove multi-line comments
                content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
                
                # Try to extract JSON if embedded in text
                if not content.startswith('{') and not content.startswith('['):
                    # Try to find JSON object
                    match = re.search(r'(\{.*\}|\[.*\])', content, re.DOTALL)
                    if match:
                        content = match.group(1)
                
                # Remove trailing commas before closing braces/brackets
                content = re.sub(r',(\s*[}\]])', r'\1', content)
                
                content = content.strip()
                
                return json.loads(content)
            
            except json.JSONDecodeError as e:
                # Log the problematic JSON for debugging
                print(f"  JSON parse error: {str(e)}")
                print(f"  Problematic JSON (first 500 chars): {content[:500]}")
                
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
