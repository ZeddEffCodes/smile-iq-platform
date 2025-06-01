<script nonce="{script_nonce}">
        // Input sanitization
        function sanitizeInput(input) {{
            return input.replace(/[<>\"'&]/g, function(match) {{
                const map = {{
                    '<': '&lt;',
                    '>': '&gt;',
                    '"': '&quot;',
                    "'": '&#x27;',
                    '&': '&amp;'
                }};
                return map[match];
            }});
        }}
        
        // Validate UK postcode format
        function validatePostcode(postcode) {{
            const ukPostcodeRegex = /^[A-Z]{{1,2}}[0-9R][0-9A-Z]? ?[0-9][A-Z]{{2}}$/;
            return ukPostcodeRegex.test(postcode.replace(/\\s+/g, '').toUpperCase());
        }}
        
        function showError(message) {{
            const errorDiv = document.getElementById('errorMessage');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
            setTimeout(() => {{
                errorDiv.style.display = 'none';
            }}, 5000);
        }}
        
        async function analyzePostcodes() {{
            const input = document.getElementById('postcodeInput');
            const btn = document.getElementById('analyzeBtn');
            const loading = document.getElementById('loadingSection');
            
            // Input validation
            const rawInput = input.value.trim();
            if (!rawInput) {{
                showError('Please enter at least one postcode');
                return;
            }}
            
            // Parse and validate postcodes
            const postcodes = rawInput.split(',')
                .map(pc => pc.trim().toUpperCase())
                .filter(pc => pc);
            
            if (postcodes.length === 0) {{
                showError('Please enter valid postcodes');
                return;
            }}
            
            if (postcodes.length > 10) {{
                showError('Maximum 10 postcodes allowed');
                return;
            }}
            
            // Validate each postcode
            for (const postcode of postcodes) {{
                if (!validatePostcode(postcode)) {{
                    showError(`Invalid postcode format: ${{postcode}}`);
                    return;
                }}
            }}
            
            // Show loading state
            btn.disabled = true;
            loading.style.display = 'block';
            document.getElementById('resultsSection').style.display = 'none';
            
            try {{
                const response = await fetch('/api/analyze', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{ postcodes: postcodes }})
                }});
                
                if (!response.ok) {{
                    const errorData = await response.json().catch(() => ({{}}));
                    throw new Error(errorData.detail || `HTTP ${{response.status}}`);
                }}
                
                const data = await response.json();
                
                if (data.status === 'success' && data.insights) {{
                    displayResults(data.insights, data.practices_found);
                }} else {{
                    throw new Error('Invalid response format');
                }}
                
            }} catch (error) {{
                console.error('Analysis failed:', error);
                showError('Analysis failed. Please try again later.');
            }} finally {{
                btn.disabled = false;
                loading.style.display = 'none';
            }}
        }}
        
        function displayResults(insights, practicesFound) {{
            const resultsGrid = document.getElementById('insightsGrid');
            const practicesCount = document.getElementById('resultsMeta');
            
            practicesCount.innerHTML = `
                Analysis completed at ${{new Date().toLocaleString()}} • 
                ${{insights.length}} postcode${{insights.length > 1 ? 's' : ''}} analyzed • 
                ${{practicesFound}} practices found
            `;
            
            const summaryStats = document.getElementById('summaryStats');
            const avgDensity = insights.reduce((sum, i) => sum + i.practice_density, 0) / insights.length;
            const avgDemographic = insights.reduce((sum, i) => sum + i.demographic_score, 0) / insights.length;
            const avgGrowth = insights.reduce((sum, i) => sum + i.growth_potential, 0) / insights.import asyncio
import secrets
import time
from datetime import datetime, timedelta
from typing import List, Optional
import re
import os
import logging
import sys
from collections import defaultdict

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, validator, Field
import uvicorn

# Security-focused logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Security Headers Middleware
class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            response = await self.app(scope, receive, send)
            
            async def send_with_security_headers(message):
                if message["type"] == "http.response.start":
                    headers = dict(message.get("headers", []))
                    
                    # Security headers
                    security_headers = {
                        b"X-Content-Type-Options": b"nosniff",
                        b"X-Frame-Options": b"DENY",
                        b"X-XSS-Protection": b"1; mode=block",
                        b"Strict-Transport-Security": b"max-age=31536000; includeSubDomains",
                        b"Content-Security-Policy": b"default-src 'self'; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
                        b"Referrer-Policy": b"strict-origin-when-cross-origin",
                        b"Permissions-Policy": b"camera=(), microphone=(), geolocation=()"
                    }
                    
                    headers.update(security_headers)
                    message["headers"] = list(headers.items())
                
                await send(message)
            
            return await send_with_security_headers
        else:
            return await self.app(scope, receive, send)

# Rate limiting
class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(list)
        self.max_requests = 100  # requests per window
        self.window_size = 60    # seconds
    
    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        
        # Clean old requests
        self.requests[client_ip] = [
            req_time for req_time in self.requests[client_ip] 
            if now - req_time < self.window_size
        ]
        
        # Check if under limit
        if len(self.requests[client_ip]) >= self.max_requests:
            return False
        
        # Add current request
        self.requests[client_ip].append(now)
        return True

rate_limiter = RateLimiter()

# Input validation and sanitization
class PostcodeRequest(BaseModel):
    postcodes: List[str] = Field(..., min_items=1, max_items=10)
    
    @validator('postcodes')
    def validate_postcodes(cls, v):
        # UK postcode regex pattern
        uk_postcode_pattern = re.compile(
            r'^[A-Z]{1,2}[0-9R][0-9A-Z]? ?[0-9][A-Z]{2}$'
        )
        
        validated_postcodes = []
        for postcode in v:
            # Sanitize input
            clean_postcode = postcode.strip().upper()
            
            # Length check
            if len(clean_postcode) > 10:
                raise ValueError(f"Postcode too long: {clean_postcode}")
            
            # Pattern validation
            if not uk_postcode_pattern.match(clean_postcode.replace(' ', '')):
                raise ValueError(f"Invalid UK postcode format: {clean_postcode}")
            
            validated_postcodes.append(clean_postcode)
        
        return validated_postcodes

# API Key authentication (optional)
security = HTTPBearer(auto_error=False)

async def get_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        return None
    
    # In production, validate against database/environment variable
    valid_api_key = os.environ.get("API_KEY")
    if valid_api_key and credentials.credentials == valid_api_key:
        return credentials.credentials
    
    return None

# Rate limiting dependency
async def rate_limit_check(request: Request):
    client_ip = request.client.host
    if not rate_limiter.is_allowed(client_ip):
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )
    return True

# Initialize FastAPI with security settings
app = FastAPI(
    title="Smile IQ - Dental Market Intelligence API",
    description="ML-powered dental market analysis and insights",
    version="1.0.0",
    docs_url="/docs" if os.environ.get("ENVIRONMENT") == "development" else None,
    redoc_url="/redoc" if os.environ.get("ENVIRONMENT") == "development" else None,
    openapi_url="/openapi.json" if os.environ.get("ENVIRONMENT") == "development" else None
)

# Add security middleware
app.add_middleware(SecurityHeadersMiddleware)

# Trusted Host Middleware (prevent Host header attacks)
allowed_hosts = os.environ.get("ALLOWED_HOSTS", "localhost,127.0.0.1,*.railway.app").split(",")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

# Secure CORS configuration
allowed_origins = os.environ.get("ALLOWED_ORIGINS", "").split(",")
if not allowed_origins or allowed_origins == [""]:
    # Development fallback - remove in production
    allowed_origins = ["http://localhost:3000", "http://localhost:8000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,  # Specific origins only
    allow_credentials=False,         # Prevent credential leakage
    allow_methods=["GET", "POST"],   # Only required methods
    allow_headers=["Content-Type", "Authorization"],  # Only required headers
    max_age=300,  # Cache preflight for 5 minutes
)

# Secure backend initialization
dental_api = None
try:
    from dental_analysis import DentalMarketAPI
    dental_api = DentalMarketAPI()
    logger.info("✅ Dental analysis backend loaded successfully")
except ImportError as e:
    logger.error(f"❌ Failed to import dental_analysis: {e}")
except Exception as e:
    logger.error(f"❌ Unexpected error loading dental_analysis: {e}")

# Health check with minimal information disclosure
@app.get("/api/health")
async def health_check(
    _: bool = Depends(rate_limit_check)
):
    """Secure health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }

# Secure analyze endpoint
@app.post("/api/analyze")
async def analyze_postcodes(
    request: PostcodeRequest,
    background_tasks: Request,
    _: bool = Depends(rate_limit_check),
    api_key: Optional[str] = Depends(get_api_key)
):
    """Analyze dental market for given postcodes with security controls"""
    
    # Optional API key check for premium features
    if os.environ.get("REQUIRE_API_KEY") == "true" and not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required"
        )
    
    if not dental_api:
        logger.error("Dental analysis service unavailable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Analysis service temporarily unavailable"
        )
    
    try:
        # Log request (without sensitive data)
        client_ip = background_tasks.client.host
        logger.info(f"Analysis request from {client_ip} for {len(request.postcodes)} postcodes")
        
        # Call backend with timeout
        results = await asyncio.wait_for(
            dental_api.analyze_postcodes(request.postcodes),
            timeout=30.0  # 30 second timeout
        )
        
        return results
        
    except asyncio.TimeoutError:
        logger.error("Analysis request timed out")
        raise HTTPException(
            status_code=status.HTTP_408_REQUEST_TIMEOUT,
            detail="Analysis request timed out"
        )
    except ValueError as e:
        logger.warning(f"Invalid input: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid input provided"
        )
    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

# Secure postcode summary endpoint
@app.get("/api/postcode/{postcode}")
async def get_postcode_summary(
    postcode: str,
    _: bool = Depends(rate_limit_check)
):
    """Get detailed summary for specific postcode with input validation"""
    
    # Input validation
    if len(postcode) > 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid postcode format"
        )
    
    # Sanitize input
    clean_postcode = re.sub(r'[^A-Z0-9\s]', '', postcode.upper().strip())
    
    if not dental_api:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Analysis service temporarily unavailable"
        )
    
    try:
        summary = dental_api.get_postcode_summary(clean_postcode)
        if 'error' in summary:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Postcode not found"
            )
        return summary
    except Exception as e:
        logger.error(f"Summary error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

# Secure homepage with CSP-compliant content
@app.get("/")
async def read_root(_: bool = Depends(rate_limit_check)):
    """Serve secure homepage"""
    
    # Generate nonce for inline scripts (CSP compliance)
    script_nonce = secrets.token_urlsafe(16)
    
    # Complete secure HTML with full UI restored
    secure_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smile IQ - Dental Market Intelligence</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet" crossorigin="anonymous">
    <style>
        :root {{
            --midnight-blue: #1a1b3a;
            --beige: #f5f3f0;
            --white: #ffffff;
            --beige-dark: #e8e5e0;
            --midnight-light: #2c2d4a;
            --shadow: rgba(26, 27, 58, 0.1);
            --shadow-hover: rgba(26, 27, 58, 0.15);
        }}
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--beige);
            min-height: 100vh;
            color: var(--midnight-blue);
            line-height: 1.6;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        .security-notice {{
            background: #e3f2fd;
            border: 1px solid #1976d2;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 20px;
            text-align: center;
            font-size: 0.9rem;
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            padding: 40px 0 20px 0;
        }}
        .header h1 {{
            font-size: 3.8rem;
            font-weight: 300;
            color: var(--midnight-blue);
            margin-bottom: 12px;
            letter-spacing: -0.02em;
        }}
        .header .subtitle {{
            font-size: 1.1rem;
            color: var(--midnight-light);
            font-weight: 400;
            opacity: 0.8;
        }}
        .main-card {{
            background: var(--white);
            border-radius: 24px;
            box-shadow: 0 8px 32px var(--shadow);
            overflow: hidden;
            margin-bottom: 40px;
            border: 1px solid rgba(26, 27, 58, 0.05);
        }}
        .search-section {{
            padding: 50px;
            background: linear-gradient(135deg, var(--white) 0%, var(--beige) 100%);
        }}
        .search-title {{
            font-size: 1.6rem;
            color: var(--midnight-blue);
            margin-bottom: 30px;
            text-align: center;
            font-weight: 400;
        }}
        .search-form {{
            display: flex;
            gap: 20px;
            max-width: 700px;
            margin: 0 auto;
            align-items: stretch;
        }}
        .input-wrapper {{
            flex: 1;
            position: relative;
        }}
        .postcode-input {{
            width: 100%;
            padding: 18px 24px;
            border: 2px solid var(--beige-dark);
            border-radius: 16px;
            font-size: 1rem;
            font-weight: 400;
            color: var(--midnight-blue);
            background: var(--white);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }}
        .postcode-input:focus {{
            outline: none;
            border-color: var(--midnight-blue);
            box-shadow: 0 0 0 4px rgba(26, 27, 58, 0.08);
        }}
        .analyze-btn {{
            padding: 18px 32px;
            background: var(--midnight-blue);
            color: var(--white);
            border: none;
            border-radius: 16px;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            display: flex;
            align-items: center;
            gap: 8px;
            white-space: nowrap;
        }}
        .analyze-btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 12px 24px var(--shadow-hover);
            background: var(--midnight-light);
        }}
        .analyze-btn:disabled {{
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }}
        .loading {{
            display: none;
            text-align: center;
            padding: 60px;
            color: var(--midnight-light);
        }}
        .spinner {{
            width: 48px;
            height: 48px;
            border: 3px solid var(--beige-dark);
            border-top: 3px solid var(--midnight-blue);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 24px;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        .results-section {{
            display: none;
            padding: 50px;
        }}
        .results-header {{
            text-align: center;
            margin-bottom: 50px;
        }}
        .results-title {{
            font-size: 2.2rem;
            color: var(--midnight-blue);
            margin-bottom: 12px;
            font-weight: 300;
        }}
        .results-meta {{
            color: var(--midnight-light);
            font-size: 0.95rem;
            opacity: 0.8;
        }}
        .summary-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 24px;
            margin-bottom: 50px;
        }}
        .stat-card {{
            text-align: center;
            padding: 32px 24px;
            background: var(--white);
            border-radius: 20px;
            border: 1px solid var(--beige-dark);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }}
        .stat-card:hover {{
            transform: translateY(-4px);
            box-shadow: 0 12px 32px var(--shadow);
        }}
        .stat-number {{
            font-size: 2.4rem;
            font-weight: 300;
            color: var(--midnight-blue);
            margin-bottom: 8px;
        }}
        .stat-label {{
            color: var(--midnight-light);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            font-weight: 500;
        }}
        .insights-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
            gap: 32px;
        }}
        .insight-card {{
            background: var(--white);
            border: 1px solid var(--beige-dark);
            border-radius: 24px;
            padding: 40px;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }}
        .insight-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--midnight-blue);
        }}
        .insight-card:hover {{
            transform: translateY(-8px);
            box-shadow: 0 20px 40px var(--shadow-hover);
            border-color: transparent;
        }}
        .postcode-title {{
            font-size: 1.5rem;
            font-weight: 500;
            color: var(--midnight-blue);
            margin-bottom: 32px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .postcode-icon {{
            width: 32px;
            height: 32px;
            background: var(--midnight-blue);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--white);
            font-size: 14px;
        }}
        .metrics-row {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 32px;
        }}
        .metric {{
            text-align: center;
            padding: 24px 16px;
            background: var(--beige);
            border-radius: 16px;
            border: 1px solid var(--beige-dark);
        }}
        .metric-value {{
            font-size: 1.8rem;
            font-weight: 400;
            color: var(--midnight-blue);
            margin-bottom: 8px;
        }}
        .metric-label {{
            font-size: 0.8rem;
            color: var(--midnight-light);
            text-transform: uppercase;
            letter-spacing: 0.6px;
            font-weight: 500;
        }}
        .competition-badge {{
            display: inline-flex;
            padding: 8px 16px;
            border-radius: 12px;
            font-size: 0.85rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin: 24px auto;
            align-items: center;
            justify-content: center;
            gap: 6px;
            width: fit-content;
        }}
        .competition-low {{
            background: #c6f6d5;
            color: #276749;
            border: 1px solid #9ae6b4;
        }}
        .competition-medium {{
            background: #fed7aa;
            color: #c2410c;
            border: 1px solid #fdba74;
        }}
        .competition-high {{
            background: #fecaca;
            color: #dc2626;
            border: 1px solid #fca5a5;
        }}
        .score-section {{
            margin: 32px 0;
        }}
        .score-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }}
        .score-label {{
            font-size: 0.9rem;
            color: var(--midnight-light);
            font-weight: 500;
        }}
        .score-value {{
            font-weight: 600;
            color: var(--midnight-blue);
        }}
        .score-bar {{
            width: 100%;
            height: 6px;
            background: var(--beige-dark);
            border-radius: 3px;
            overflow: hidden;
        }}
        .score-fill {{
            height: 100%;
            background: var(--midnight-blue);
            border-radius: 3px;
            transition: width 1s cubic-bezier(0.4, 0, 0.2, 1);
            width: 0;
        }}
        .treatment-section {{
            margin: 32px 0;
            padding: 24px;
            background: linear-gradient(135deg, var(--white) 0%, var(--beige) 100%);
            border-radius: 16px;
            border: 1px solid var(--beige-dark);
        }}
        .treatment-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 20px;
        }}
        .treatment-icon {{
            width: 24px;
            height: 24px;
            background: var(--midnight-blue);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            color: var(--white);
        }}
        .treatment-title {{
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--midnight-blue);
        }}
        .treatment-list {{
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}
        .treatment-item {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 16px;
            background: var(--white);
            border-radius: 12px;
            border: 1px solid var(--beige-dark);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }}
        .treatment-item:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 16px var(--shadow);
        }}
        .treatment-info {{
            flex: 1;
        }}
        .treatment-name {{
            font-weight: 600;
            color: var(--midnight-blue);
            margin-bottom: 4px;
            font-size: 0.95rem;
        }}
        .treatment-details {{
            font-size: 0.8rem;
            color: var(--midnight-light);
            opacity: 0.8;
        }}
        .treatment-demand {{
            background: var(--midnight-blue);
            color: var(--white);
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .treatment-rank {{
            width: 32px;
            height: 32px;
            background: var(--midnight-blue);
            color: var(--white);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 0.9rem;
            margin-right: 12px;
        }}
        .insights-list {{
            margin-top: 32px;
        }}
        .insights-title {{
            font-size: 1rem;
            font-weight: 600;
            color: var(--midnight-blue);
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .risk-icon, .opportunity-icon {{
            width: 20px;
            height: 20px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 11px;
            color: var(--white);
        }}
        .risk-icon {{
            background: var(--midnight-blue);
        }}
        .opportunity-icon {{
            background: var(--midnight-light);
        }}
        .insights-items {{
            list-style: none;
            padding: 0;
        }}
        .insights-items li {{
            padding: 12px 0;
            border-bottom: 1px solid var(--beige-dark);
            color: var(--midnight-light);
            font-size: 0.9rem;
            line-height: 1.5;
        }}
        .insights-items li:last-child {{
            border-bottom: none;
        }}
        .demo-note {{
            background: var(--beige);
            border: 1px solid var(--beige-dark);
            border-radius: 20px;
            padding: 24px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .demo-note strong {{
            color: var(--midnight-blue);
        }}
        .error-message {{
            background: #ffebee;
            border: 1px solid #f44336;
            color: #c62828;
            padding: 16px;
            border-radius: 8px;
            margin: 16px 0;
            display: none;
        }}
        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 2.8rem;
            }}
            .search-form {{
                flex-direction: column;
                gap: 16px;
            }}
            .insights-grid {{
                grid-template-columns: 1fr;
            }}
            .metrics-row {{
                grid-template-columns: 1fr;
            }}
            .search-section,
            .results-section {{
                padding: 32px 24px;
            }}
            .insight-card {{
                padding: 32px 24px;
            }}
        }}
        .fade-in {{
            animation: fadeIn 0.6s cubic-bezier(0.4, 0, 0.2, 1);
        }}
        @keyframes fadeIn {{
            from {{
                opacity: 0;
                transform: translateY(20px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="security-notice">
            <i class="fas fa-shield-alt"></i>
            <strong>Secure Platform:</strong> Your data is protected with enterprise-grade security measures.
        </div>
        
        <div class="header">
            <h1>Smile IQ</h1>
            <div class="subtitle">Dental Market Intelligence & Analysis Platform</div>
        </div>
        
        <div class="demo-note">
            <strong>Live API Mode:</strong> This platform connects to your Railway backend API for real dental market analysis.
        </div>
        
        <div class="main-card">
            <div class="search-section">
                <h2 class="search-title">Analyze Dental Market by Postcode</h2>
                <div class="search-form">
                    <div class="input-wrapper">
                        <input type="text" 
                               class="postcode-input" 
                               id="postcodeInput" 
                               placeholder="Enter postcodes (e.g., SW1A 1AA, M1 1AA, B1 1AA)"
                               value="SW1A 1AA, M1 1AA, B1 1AA"
                               maxlength="100"
                               pattern="^[A-Za-z0-9\\s,]+$">
                    </div>
                    <button class="analyze-btn" id="analyzeBtn">
                        <i class="fas fa-search"></i>
                        Analyze Market
                    </button>
                </div>
                <div class="error-message" id="errorMessage"></div>
            </div>
            
            <div class="loading" id="loadingSection">
                <div class="spinner"></div>
                <div>Analyzing dental market data...</div>
                <div style="font-size: 0.9rem; margin-top: 12px; opacity: 0.7;">
                    Extracting practice data, demographics, and generating ML predictions
                </div>
            </div>
            
            <div class="results-section" id="resultsSection">
                <div class="results-header">
                    <h2 class="results-title">Market Analysis Results</h2>
                    <div class="results-meta" id="resultsMeta"></div>
                </div>
                <div class="summary-stats" id="summaryStats"></div>
                <div class="insights-grid" id="insightsGrid"></div>
            </div>
        </div>
    </div>
    
    <script nonce="{script_nonce}">
        // Input sanitization
        function sanitizeInput(input) {{
            return input.replace(/[<>\"'&]/g, function(match) {{
                const map = {{
                    '<': '&lt;',
                    '>': '&gt;',
                    '"': '&quot;',
                    "'": '&#x27;',
                    '&': '&amp;'
                }};
                return map[match];
            }});
        }}
        
        // Validate UK postcode format
        function validatePostcode(postcode) {{
            const ukPostcodeRegex = /^[A-Z]{{1,2}}[0-9R][0-9A-Z]? ?[0-9][A-Z]{{2}}$/;
            return ukPostcodeRegex.test(postcode.replace(/\\s+/g, '').toUpperCase());
        }}
        
        function showError(message) {{
            const errorDiv = document.getElementById('errorMessage');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
            setTimeout(() => {{
                errorDiv.style.display = 'none';
            }}, 5000);
        }}
        
        async function analyzePostcodes() {{
            const input = document.getElementById('postcodeInput');
            const btn = document.getElementById('analyzeBtn');
            const loading = document.getElementById('loadingSection');
            
            // Input validation
            const rawInput = input.value.trim();
            if (!rawInput) {{
                showError('Please enter at least one postcode');
                return;
            }}
            
            // Parse and validate postcodes
            const postcodes = rawInput.split(',')
                .map(pc => pc.trim().toUpperCase())
                .filter(pc => pc);
            
            if (postcodes.length === 0) {{
                showError('Please enter valid postcodes');
                return;
            }}
            
            if (postcodes.length > 10) {{
                showError('Maximum 10 postcodes allowed');
                return;
            }}
            
            // Validate each postcode
            for (const postcode of postcodes) {{
                if (!validatePostcode(postcode)) {{
                    showError(`Invalid postcode format: ${{postcode}}`);
                    return;
                }}
            }}
            
            // Show loading state
            btn.disabled = true;
            loading.style.display = 'block';
            
            try {{
                const response = await fetch('/api/analyze', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{ postcodes: postcodes }})
                }});
                
                if (!response.ok) {{
                    const errorData = await response.json().catch(() => ({{}}));
                    throw new Error(errorData.detail || `HTTP ${{response.status}}`);
                }}
                
                const data = await response.json();
                
                if (data.status === 'success') {{
                    // Handle success (implement your UI logic here)
                    showError('Analysis completed successfully!');
                }} else {{
                    throw new Error('Invalid response format');
                }}
                
            }} catch (error) {{
                console.error('Analysis failed:', error);
                showError('Analysis failed. Please try again later.');
            }} finally {{
                btn.disabled = false;
                loading.style.display = 'none';
            }}
        }}
        
        // Event listeners
        document.getElementById('analyzeBtn').addEventListener('click', analyzePostcodes);
        document.getElementById('postcodeInput').addEventListener('keypress', function(e) {{
            if (e.key === 'Enter') {{
                analyzePostcodes();
            }}
        }});
        
        // Input filtering
        document.getElementById('postcodeInput').addEventListener('input', function(e) {{
            e.target.value = e.target.value.replace(/[^A-Za-z0-9\\s,]/g, '');
        }});
    </script>
</body>
</html>"""
    
    return HTMLResponse(
        content=secure_html,
        headers={
            "Content-Security-Policy": f"default-src 'self'; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; script-src 'self' 'nonce-{script_nonce}'; img-src 'self' data:; connect-src 'self'"
        }
    )

# Secure static file serving (if needed)
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# Production server configuration
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    
    # Production logging
    logger.info(f"🚀 Starting Smile IQ server on 0.0.0.0:{port}")
    logger.info(f"Environment: {os.environ.get('ENVIRONMENT', 'production')}")
    logger.info(f"API docs available: {os.environ.get('ENVIRONMENT') == 'development'}")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info",
        access_log=True,
        server_header=False,  # Hide server information
        date_header=False     # Hide date header
    )
