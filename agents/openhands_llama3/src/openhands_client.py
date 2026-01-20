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
        max_retries: int = 1
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
                response = litellm.completion(
                    messages=messages,
                    **self.llm_kwargs
                )
                
                # Extract content from response
                content = response.choices[0].message.content
                
                # Try to parse JSON
                # Remove markdown code blocks if present
                content = content.strip()
                if content.startswith("```json"):
                    content = content[7:]
                if content.startswith("```"):
                    content = content[3:]
                if content.endswith("```"):
                    content = content[:-3]
                content = content.strip()
                
                return json.loads(content)
            
            except json.JSONDecodeError as e:
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
                        f"Last error: {str(e)}"
                    ) from e
