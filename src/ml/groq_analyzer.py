# src/ml/groq_analyzer.py - COMPLETE FIXED VERSION
import os
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import asyncio
import aiohttp
from datetime import datetime, timedelta
import hashlib

@dataclass
class GroqExplanation:
    """Enhanced AI explanation from Groq"""
    vulnerability_type: str
    severity_assessment: str
    detailed_explanation: str
    attack_scenario: str
    business_impact: str
    fix_recommendation: str
    code_example: str
    references: List[str]
    confidence: float
    
class GroqCloudAnalyzer:
    """Integrates Groq Cloud API for advanced vulnerability explanations using Llama 3 70B"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        if not self.api_key:
            print("Warning: GROQ_API_KEY not found in environment. Groq features disabled.")
            print("To enable: Add GROQ_API_KEY=your-key to .env file")
            self.enabled = False
            return
            
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"
        self.model = "llama3-70b-8192"  # Llama 3 70B model
        self.enabled = True
        
        # Cache for API responses (to save costs)
        self.cache_dir = "data/groq_cache"
        os.makedirs(self.cache_dir, exist_ok=True)
        
        print("✓ Groq Cloud Analyzer initialized with Llama 3 70B")
    
    async def analyze_vulnerability(self, 
                                  code_snippet: str,
                                  vulnerability_info: Dict[str, Any],
                                  language: str) -> GroqExplanation:
        """Get advanced AI analysis of a vulnerability"""
        if not self.enabled:
            return self._create_fallback_explanation(vulnerability_info)
        
        # Limit code snippet size to avoid token limits
        if len(code_snippet) > 300:
            code_snippet = code_snippet[:300] + "..."
        
        # Check cache first
        cache_key = self._get_cache_key(code_snippet, vulnerability_info)
        cached = self._get_cached_response(cache_key)
        if cached:
            return cached
        
        # Prepare the prompt
        prompt = self._create_analysis_prompt(code_snippet, vulnerability_info, language)
        
        # Call Groq API with retry for rate limits
        retries = 3
        for attempt in range(retries):
            try:
                response = await self._call_groq_api(prompt)
                explanation = self._parse_response(response, vulnerability_info)
                
                # Cache the response
                self._cache_response(cache_key, explanation)
                
                return explanation
                
            except Exception as e:
                if "rate_limit_exceeded" in str(e) and attempt < retries - 1:
                    wait_time = 5 * (attempt + 1)  # Exponential backoff
                    print(f"Rate limit hit, waiting {wait_time}s...")
                    await asyncio.sleep(wait_time)
                else:
                    print(f"Groq API error: {e}")
                    return self._create_fallback_explanation(vulnerability_info)
        
        return self._create_fallback_explanation(vulnerability_info)
    
    def _create_analysis_prompt(self, code: str, vuln_info: Dict, language: str) -> str:
        """Create a detailed prompt for Llama 3 70B"""
        prompt = f"""You are an expert security researcher analyzing code vulnerabilities. 
Analyze this {language} code with a detected {vuln_info.get('type', 'security')} vulnerability:

```{language}
{code}
```

Vulnerability Details:
- Type: {vuln_info.get('type', 'Unknown')}
- Severity: {vuln_info.get('severity', 'Medium')}
- Line: {vuln_info.get('line', 'Unknown')}

Provide a security analysis as a valid JSON object with exactly these fields:
{{
    "severity_assessment": "Why this severity level is appropriate",
    "detailed_explanation": "Technical explanation of the vulnerability",
    "attack_scenario": "Realistic attack scenario",
    "business_impact": "Potential business impact",
    "fix_recommendation": "Specific actionable fix",
    "secure_code_example": "Corrected code example",
    "references": ["url1", "url2", "url3"]
}}

IMPORTANT: Return ONLY valid JSON. No extra text. Ensure all strings are properly escaped."""
        
        return prompt
    
    async def _call_groq_api(self, prompt: str) -> Dict:
        """Make async API call to Groq"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a senior security researcher. Always respond with valid JSON only."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.3,
            "max_tokens": 1200  # Reduced to avoid token limits
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(self.base_url, headers=headers, json=payload) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"Groq API error {response.status}: {error_text}")
                
                return await response.json()
    
    def _parse_response(self, response: Dict, vuln_info: Dict) -> GroqExplanation:
        """Parse Groq API response into structured explanation"""
        try:
            # Extract the generated content
            content = response['choices'][0]['message']['content']
            
            # Clean up the content (remove any markdown code blocks)
            content = content.strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
            if content.endswith("```"):
                content = content[:-3]
            
            try:
                # Parse JSON response
                analysis = json.loads(content.strip())
            except json.JSONDecodeError as e:
                print(f"JSON parse error: {e}")
                print(f"Content: {content[:200]}...")
                # Try to extract JSON from the content
                import re
                json_match = re.search(r'\{.*\}', content, re.DOTALL)
                if json_match:
                    try:
                        analysis = json.loads(json_match.group())
                    except:
                        raise e
                else:
                    raise e
            
            return GroqExplanation(
                vulnerability_type=vuln_info.get('type', 'Unknown'),
                severity_assessment=analysis.get('severity_assessment', ''),
                detailed_explanation=analysis.get('detailed_explanation', ''),
                attack_scenario=analysis.get('attack_scenario', ''),
                business_impact=analysis.get('business_impact', ''),
                fix_recommendation=analysis.get('fix_recommendation', ''),
                code_example=analysis.get('secure_code_example', ''),
                references=analysis.get('references', []),
                confidence=0.95  # High confidence for Llama 3 70B
            )
            
        except Exception as e:
            print(f"Error parsing Groq response: {e}")
            return self._create_fallback_explanation(vuln_info)
    
    def _create_fallback_explanation(self, vuln_info: Dict) -> GroqExplanation:
        """Create basic explanation if API fails"""
        return GroqExplanation(
            vulnerability_type=vuln_info.get('type', 'Unknown'),
            severity_assessment=f"{vuln_info.get('severity', 'Medium')} severity based on pattern analysis",
            detailed_explanation=f"A {vuln_info.get('type', 'security')} vulnerability was detected. Groq API unavailable for detailed analysis.",
            attack_scenario="An attacker could potentially exploit this vulnerability",
            business_impact="Could lead to security breach if exploited",
            fix_recommendation="Review and fix the vulnerable code pattern",
            code_example="// Fix implementation needed",
            references=["https://cwe.mitre.org/"],
            confidence=0.5
        )
    
    def _get_cache_key(self, code: str, vuln_info: Dict) -> str:
        """Generate cache key for the analysis"""
        content = f"{code}:{vuln_info.get('type')}:{vuln_info.get('line')}"
        return hashlib.md5(content.encode()).hexdigest()
    
    def _get_cached_response(self, cache_key: str) -> Optional[GroqExplanation]:
        """Retrieve cached response if available"""
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
        
        if os.path.exists(cache_file):
            # Check if cache is fresh (24 hours)
            file_time = datetime.fromtimestamp(os.path.getmtime(cache_file))
            if datetime.now() - file_time < timedelta(hours=24):
                try:
                    with open(cache_file, 'r') as f:
                        data = json.load(f)
                        return GroqExplanation(**data)
                except:
                    pass
        return None
    
    def _cache_response(self, cache_key: str, explanation: GroqExplanation):
        """Cache the response for future use"""
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.json")
        
        try:
            with open(cache_file, 'w') as f:
                json.dump({
                    'vulnerability_type': explanation.vulnerability_type,
                    'severity_assessment': explanation.severity_assessment,
                    'detailed_explanation': explanation.detailed_explanation,
                    'attack_scenario': explanation.attack_scenario,
                    'business_impact': explanation.business_impact,
                    'fix_recommendation': explanation.fix_recommendation,
                    'code_example': explanation.code_example,
                    'references': explanation.references,
                    'confidence': explanation.confidence
                }, f, indent=2)
        except:
            pass  # Ignore cache errors
    
    async def batch_analyze(self, vulnerabilities: List[Dict]) -> List[GroqExplanation]:
        """Analyze multiple vulnerabilities efficiently with rate limiting"""
        tasks = []
        
        for vuln in vulnerabilities:
            task = self.analyze_vulnerability(
                vuln.get('code_snippet', '')[:300],  # Limit size
                vuln,
                vuln.get('language', 'python')
            )
            tasks.append(task)
        
        # Process in smaller batches with longer delays
        results = []
        batch_size = 2  # Reduced from 5
        
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, Exception):
                    print(f"Batch analysis error: {result}")
                    results.append(self._create_fallback_explanation({}))
                else:
                    results.append(result)
            
            # Always pause between batches
            if i + batch_size < len(tasks):
                await asyncio.sleep(3)  # Increased delay
        
        return results
    
    def format_explanation_for_display(self, explanation: GroqExplanation) -> str:
        """Format explanation for user display"""
        formatted = f"""
🔍 AI Security Analysis (Powered by Llama 3 70B)
{'='*60}

🎯 Vulnerability: {explanation.vulnerability_type}

📊 Severity Assessment:
{explanation.severity_assessment}

🔬 Technical Details:
{explanation.detailed_explanation}

⚔️ Attack Scenario:
{explanation.attack_scenario}

💼 Business Impact:
{explanation.business_impact}

🛠️ Fix Recommendation:
{explanation.fix_recommendation}

📝 Secure Code Example:
```
{explanation.code_example}
```

📚 References:
"""
        for ref in explanation.references:
            formatted += f"   • {ref}\n"
        
        formatted += f"\n🤖 AI Confidence: {explanation.confidence:.0%}"
        
        return formatted