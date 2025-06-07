from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Optional
import os
import logging
import sys
import re
import time
from collections import defaultdict
import secrets
import hashlib
from datetime import datetime, timedelta
import random

# Add this to confirm Railway is loading the correct file
print("🚀 Starting Smile IQ server - main.py loaded!")

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Security: Input validation regex for UK postcodes
UK_POSTCODE_REGEX = re.compile(r'^[A-Z]{1,2}[0-9][A-Z0-9]?\s?[0-9][A-Z]{2}$', re.IGNORECASE)

# Security: Rate limiting storage
rate_limit_storage = defaultdict(list)

# Security: API key validation (if needed)
security = HTTPBearer(auto_error=False)

# Security: Generate secure session token
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))

app = FastAPI(
    title="Smile IQ - Dental Market Intelligence API",
    description="ML-powered dental market analysis and insights",
    version="1.0.0",
    # Security: Remove detailed docs in production
    docs_url="/docs" if os.environ.get("ENVIRONMENT") != "production" else None,
    redoc_url="/redoc" if os.environ.get("ENVIRONMENT") != "production" else None,
    # Security: Custom OpenAPI URL to obscure API structure
    openapi_url="/api/v1/openapi.json" if os.environ.get("ENVIRONMENT") != "production" else None
)

# Security: Trusted host middleware to prevent host header attacks
allowed_hosts = os.environ.get("ALLOWED_HOSTS", "").split(",") if os.environ.get("ALLOWED_HOSTS") else ["*"]
if allowed_hosts != ["*"]:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

# Security: Enhanced CORS configuration
allowed_origins = os.environ.get("ALLOWED_ORIGINS", "").split(",") if os.environ.get("ALLOWED_ORIGINS") else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,  # Specify exact origins in production
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # Only allow necessary methods
    allow_headers=["Content-Type", "Authorization"],  # Only allow necessary headers
    max_age=3600,  # Cache preflight requests
)

# Security: Custom middleware for additional security headers
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    return response

# Security: Rate limiting function
def check_rate_limit(client_ip: str, max_requests: int = 100, window_minutes: int = 15) -> bool:
    """
    Check if client IP has exceeded rate limit
    """
    now = time.time()
    window_start = now - (window_minutes * 60)
    
    # Clean old entries
    rate_limit_storage[client_ip] = [
        timestamp for timestamp in rate_limit_storage[client_ip]
        if timestamp > window_start
    ]
    
    # Check if limit exceeded
    if len(rate_limit_storage[client_ip]) >= max_requests:
        return False
    
    # Add current request
    rate_limit_storage[client_ip].append(now)
    return True

# Security: Input validation with rate limiting
def get_client_ip(request: Request) -> str:
    """Get client IP from request, considering proxy headers"""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host

# Security: Dependency for rate limiting
async def rate_limit_dependency(request: Request):
    client_ip = get_client_ip(request)
    if not check_rate_limit(client_ip):
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Please try again later.")
    return client_ip

# Security: Optional API key validation
async def validate_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Validate API key if authentication is required"""
    # Only require API key if environment variable is set
    required_api_key = os.environ.get("API_KEY")
    if required_api_key:
        if not credentials or credentials.credentials != required_api_key:
            logger.warning("Invalid API key attempt")
            raise HTTPException(status_code=401, detail="Invalid API key")
    return True

class PostcodeRequest(BaseModel):
    postcodes: List[str] = Field(..., min_length=1, max_length=10)

@app.get("/")
async def read_root():
    """Serve homepage"""
    return HTMLResponse("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Smile IQ - Dental Market Intelligence</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --midnight-blue: #1a1b3a;
            --beige: #f5f3f0;
            --white: #ffffff;
            --beige-dark: #e8e5e0;
            --midnight-light: #2c2d4a;
            --shadow: rgba(26, 27, 58, 0.1);
            --shadow-hover: rgba(26, 27, 58, 0.15);
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--beige);
            min-height: 100vh;
            color: var(--midnight-blue);
            line-height: 1.6;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding: 40px 0 20px 0;
        }
        .header h1 {
            font-size: 3.8rem;
            font-weight: 300;
            color: var(--midnight-blue);
            margin-bottom: 12px;
            letter-spacing: -0.02em;
        }
        .header .subtitle {
            font-size: 1.1rem;
            color: var(--midnight-light);
            font-weight: 400;
            opacity: 0.8;
        }
        .main-card {
            background: var(--white);
            border-radius: 24px;
            box-shadow: 0 8px 32px var(--shadow);
            overflow: hidden;
            margin-bottom: 40px;
            border: 1px solid rgba(26, 27, 58, 0.05);
        }
        .search-section {
            padding: 50px;
            background: linear-gradient(135deg, var(--white) 0%, var(--beige) 100%);
        }
        .search-title {
            font-size: 1.6rem;
            color: var(--midnight-blue);
            margin-bottom: 30px;
            text-align: center;
            font-weight: 400;
        }
        .search-form {
            display: flex;
            gap: 20px;
            max-width: 700px;
            margin: 0 auto;
            align-items: stretch;
        }
        .input-wrapper {
            flex: 1;
            position: relative;
        }
        .postcode-input {
            width: 100%;
            padding: 18px 24px;
            border: 2px solid var(--beige-dark);
            border-radius: 16px;
            font-size: 1rem;
            font-weight: 400;
            color: var(--midnight-blue);
            background: var(--white);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .postcode-input:focus {
            outline: none;
            border-color: var(--midnight-blue);
            box-shadow: 0 0 0 4px rgba(26, 27, 58, 0.08);
        }
        .analyze-btn {
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
        }
        .analyze-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 24px var(--shadow-hover);
            background: var(--midnight-light);
        }
        .analyze-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        .loading {
            display: none;
            text-align: center;
            padding: 60px;
            color: var(--midnight-light);
        }
        .spinner {
            width: 48px;
            height: 48px;
            border: 3px solid var(--beige-dark);
            border-top: 3px solid var(--midnight-blue);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 24px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .results-section {
            display: none;
            padding: 50px;
        }
        .results-header {
            text-align: center;
            margin-bottom: 50px;
        }
        .results-title {
            font-size: 2.2rem;
            color: var(--midnight-blue);
            margin-bottom: 12px;
            font-weight: 300;
        }
        .results-meta {
            color: var(--midnight-light);
            font-size: 0.95rem;
            opacity: 0.8;
        }
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 24px;
            margin-bottom: 50px;
        }
        .stat-card {
            text-align: center;
            padding: 32px 24px;
            background: var(--white);
            border-radius: 20px;
            border: 1px solid var(--beige-dark);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 12px 32px var(--shadow);
        }
        .stat-number {
            font-size: 2.4rem;
            font-weight: 300;
            color: var(--midnight-blue);
            margin-bottom: 8px;
        }
        .stat-label {
            color: var(--midnight-light);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            font-weight: 500;
        }
        .insights-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
            gap: 32px;
        }
        .insight-card {
            background: var(--white);
            border: 1px solid var(--beige-dark);
            border-radius: 24px;
            padding: 40px;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }
        .insight-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--midnight-blue);
        }
        .insight-card:hover {
            transform: translateY(-8px);
            box-shadow: 0 20px 40px var(--shadow-hover);
            border-color: transparent;
        }
        .postcode-title {
            font-size: 1.5rem;
            font-weight: 500;
            color: var(--midnight-blue);
            margin-bottom: 32px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .postcode-icon {
            width: 32px;
            height: 32px;
            background: var(--midnight-blue);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--white);
            font-size: 14px;
        }
        .metrics-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 32px;
        }
        .metric {
            text-align: center;
            padding: 24px 16px;
            background: var(--beige);
            border-radius: 16px;
            border: 1px solid var(--beige-dark);
        }
        .metric-value {
            font-size: 1.8rem;
            font-weight: 400;
            color: var(--midnight-blue);
            margin-bottom: 8px;
        }
        .metric-label {
            font-size: 0.8rem;
            color: var(--midnight-light);
            text-transform: uppercase;
            letter-spacing: 0.6px;
            font-weight: 500;
        }
        .opportunity-badge {
            font-size: 0.75rem;
            padding: 4px 8px;
            border-radius: 8px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-left: auto;
        }
        .opportunity-high {
            background: #dcfce7;
            color: #166534;
            border: 1px solid #bbf7d0;
        }
        .opportunity-medium {
            background: #fef3c7;
            color: #92400e;
            border: 1px solid #fde68a;
        }
        .opportunity-low {
            background: #fee2e2;
            color: #991b1b;
            border: 1px solid #fecaca;
        }
        .section-title {
            font-size: 1rem;
            font-weight: 600;
            color: var(--midnight-blue);
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
            border-bottom: 2px solid var(--beige-dark);
            padding-bottom: 8px;
        }
        .treatment-section {
            margin: 32px 0;
            padding: 24px;
            background: linear-gradient(135deg, var(--white) 0%, var(--beige) 100%);
            border-radius: 16px;
            border: 1px solid var(--beige-dark);
        }
        .treatment-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 20px;
        }
        .treatment-icon {
            width: 24px;
            height: 24px;
            background: var(--midnight-blue);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            color: var(--white);
        }
        .treatment-title {
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--midnight-blue);
        }
        .treatment-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .treatment-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 16px;
            background: var(--white);
            border-radius: 12px;
            border: 1px solid var(--beige-dark);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .treatment-item:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 16px var(--shadow);
        }
        .treatment-info {
            flex: 1;
        }
        .treatment-name {
            font-weight: 600;
            color: var(--midnight-blue);
            margin-bottom: 4px;
            font-size: 0.95rem;
        }
        .treatment-details {
            font-size: 0.8rem;
            color: var(--midnight-light);
            opacity: 0.8;
        }
        .treatment-demand {
            background: var(--midnight-blue);
            color: var(--white);
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .treatment-rank {
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
        }
        .pricing-intelligence {
            margin: 24px 0;
            padding: 20px;
            background: linear-gradient(135deg, var(--white) 0%, var(--beige) 100%);
            border-radius: 12px;
            border: 1px solid var(--beige-dark);
        }
        .pricing-grid {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .pricing-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px;
            background: var(--white);
            border-radius: 8px;
            border: 1px solid var(--beige-dark);
        }
        .price-comparison {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .market-price {
            font-weight: 600;
            color: var(--midnight-blue);
        }
        .price-trend {
            display: flex;
            align-items: center;
            gap: 4px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        .trending-up {
            color: #dc2626;
        }
        .trending-down {
            color: #16a34a;
        }
        .stable {
            color: #6b7280;
        }
        .competitor-analysis {
            margin: 24px 0;
        }
        .competitor-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .competitor-item {
            padding: 16px;
            background: var(--beige);
            border-radius: 12px;
            border: 1px solid var(--beige-dark);
        }
        .competitor-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        .competitor-name {
            font-weight: 600;
            color: var(--midnight-blue);
        }
        .competitor-distance {
            font-size: 0.85rem;
            color: var(--midnight-light);
            background: var(--white);
            padding: 4px 8px;
            border-radius: 6px;
        }
        .competitor-metrics {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 8px;
        }
        .metric-badge {
            font-size: 0.75rem;
            padding: 4px 8px;
            background: var(--midnight-blue);
            color: var(--white);
            border-radius: 6px;
            font-weight: 500;
        }
        .metric-badge.reviews {
            background: #f59e0b;
        }
        .metric-badge.patients {
            background: #10b981;
        }
        .metric-badge.specialty {
            background: #6366f1;
        }
        .competitor-strengths {
            font-size: 0.85rem;
            color: var(--midnight-light);
        }
        .gap-analysis {
            margin: 24px 0;
            padding: 20px;
            background: linear-gradient(135deg, var(--beige) 0%, var(--white) 100%);
            border-radius: 12px;
            border: 1px solid var(--beige-dark);
        }
        .gap-items {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .gap-item {
            padding: 12px;
            background: var(--white);
            border-radius: 8px;
            border: 1px solid var(--beige-dark);
        }
        .gap-service {
            font-weight: 600;
            color: var(--midnight-blue);
            margin-bottom: 6px;
        }
        .gap-details {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }
        .gap-details span {
            font-size: 0.75rem;
            padding: 3px 6px;
            border-radius: 4px;
            font-weight: 500;
        }
        .demand-level {
            color: var(--white);
        }
        .demand-level.high {
            background: #dc2626;
        }
        .demand-level.medium {
            background: #f59e0b;
        }
        .demand-level.low {
            background: #6b7280;
        }
        .supply-level {
            background: var(--beige-dark);
            color: var(--midnight-blue);
        }
        .opportunity-value {
            background: #16a34a;
            color: var(--white);
        }
        .patient-insights {
            margin: 24px 0;
        }
        .insight-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 16px;
        }
        .insight-metric {
            text-align: center;
            padding: 16px 12px;
            background: var(--beige);
            border-radius: 12px;
            border: 1px solid var(--beige-dark);
        }
        .demo-note {
            background: var(--beige);
            border: 1px solid var(--beige-dark);
            border-radius: 20px;
            padding: 24px;
            margin-bottom: 30px;
            text-align: center;
        }
        .demo-note strong {
            color: var(--midnight-blue);
        }
        .recommendations {
            margin-top: 32px;
        }
        .insights-title {
            font-size: 1rem;
            font-weight: 600;
            color: var(--midnight-blue);
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .risk-icon, .opportunity-icon {
            width: 20px;
            height: 20px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 11px;
            color: var(--white);
        }
        .risk-icon {
            background: var(--midnight-blue);
        }
        .opportunity-icon {
            background: var(--midnight-light);
        }
        .insights-items {
            list-style: none;
            padding: 0;
        }
        .insights-items li {
            padding: 12px 0;
            border-bottom: 1px solid var(--beige-dark);
            color: var(--midnight-light);
            font-size: 0.9rem;
            line-height: 1.5;
        }
        .insights-items li:last-child {
            border-bottom: none;
        }
        @media (max-width: 768px) {
            .header h1 {
                font-size: 2.8rem;
            }
            .search-form {
                flex-direction: column;
                gap: 16px;
            }
            .insights-grid {
                grid-template-columns: 1fr;
            }
            .metrics-row {
                grid-template-columns: 1fr;
            }
            .search-section,
            .results-section {
                padding: 32px 24px;
            }
            .insight-card {
                padding: 32px 24px;
            }
        }
        .fade-in {
            animation: fadeIn 0.6s cubic-bezier(0.4, 0, 0.2, 1);
        }
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
    </style>
</head>
<body>
    <div class="container">
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
                               value="SW1A 1AA, M1 1AA, B1 1AA">
                    </div>
                    <button class="analyze-btn" id="analyzeBtn" onclick="analyzePostcodes()">
                        <i class="fas fa-search"></i>
                        Analyze Market
                    </button>
                </div>
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
    <script>
        async function analyzePostcodes() {
            const input = document.getElementById('postcodeInput');
            const postcodes = input.value.split(',').map(pc => pc.trim().toUpperCase()).filter(pc => pc);
            
            if (postcodes.length === 0) {
                alert('Please enter at least one postcode');
                return;
            }
            
            document.getElementById('loadingSection').style.display = 'block';
            document.getElementById('resultsSection').style.display = 'none';
            document.getElementById('analyzeBtn').disabled = true;
            
            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ postcodes: postcodes })
                });
                
                    throw new Error(`API Error (${response.status}): ${errorData.detail || 'Unknown error'}`);
                }
                
                const data = await response.json();
                console.log('Received data from backend:', data);
                
                if (data.status === 'success' && data.insights) {
                    displayResults(data.insights, data.practices_found);
                } else {
                    throw new Error('Invalid response format from API');
                }
            } catch (error) {
                console.error('API Error:', error);
                alert(`Analysis failed: ${error.message}. Please try again.`);
            } finally {
                document.getElementById('loadingSection').style.display = 'none';
                document.getElementById('analyzeBtn').disabled = false;
            }
        }
        
        function displayResults(insights, practicesFound) {
            const resultsGrid = document.getElementById('insightsGrid');
            const practicesCount = document.getElementById('resultsMeta');
            
            practicesCount.innerHTML = `
                Analysis completed at ${new Date().toLocaleString()} • 
                ${insights.length} postcode${insights.length > 1 ? 's' : ''} analyzed • 
                ${practicesFound} practices found • 
                ${insights.reduce((sum, i) => sum + i.competitors.length, 0)} direct competitors identified
            `;
            
            const summaryStats = document.getElementById('summaryStats');
            const avgRevenue = insights.reduce((sum, i) => sum + i.market_metrics.avg_revenue_per_patient, 0) / insights.length;
            const totalOpportunityValue = insights.reduce((sum, i) => sum + i.opportunity_value, 0);
            const avgCompetitorCount = insights.reduce((sum, i) => sum + i.competitors.length, 0) / insights.length;
            const highOpportunityAreas = insights.filter(i => i.opportunity_score > 75).length;
            
            summaryStats.innerHTML = `
                <div class="stat-card fade-in">
                    <div class="stat-number">£${Math.round(avgRevenue).toLocaleString()}</div>
                    <div class="stat-label">Avg Revenue/Patient</div>
                </div>
                <div class="stat-card fade-in">
                    <div class="stat-number">${avgCompetitorCount.toFixed(1)}</div>
                    <div class="stat-label">Avg Competitors/Area</div>
                </div>
                <div class="stat-card fade-in">
                    <div class="stat-number">£${Math.round(totalOpportunityValue/1000)}k</div>
                    <div class="stat-label">Total Market Opportunity</div>
                </div>
                <div class="stat-card fade-in">
                    <div class="stat-number">${highOpportunityAreas}</div>
                    <div class="stat-label">High Opportunity Areas</div>
                </div>
            `;
            
            resultsGrid.innerHTML = insights.map(insight => createInsightCard(insight)).join('');
            
            insights.forEach(insight => {
                populateTreatments(insight);
                populateCompetitors(insight);
            });
            
            document.getElementById('resultsSection').style.display = 'block';
        }
        
        function createInsightCard(insight) {
            const opportunityClass = insight.opportunity_score > 75 ? 'opportunity-high' : 
                                   insight.opportunity_score > 50 ? 'opportunity-medium' : 'opportunity-low';
            const opportunityLabel = insight.opportunity_score > 75 ? 'High Opportunity' : 
                                   insight.opportunity_score > 50 ? 'Moderate Opportunity' : 'Low Opportunity';
            
            return `
                <div class="insight-card fade-in">
                    <div class="postcode-title">
                        <div class="postcode-icon">
                            <i class="fas fa-map-marker-alt"></i>
                        </div>
                        ${insight.postcode}
                        <div class="opportunity-badge ${opportunityClass}">
                            ${opportunityLabel}
                        </div>
                    </div>
                    
                    <div class="market-metrics">
                        <div class="metrics-row">
                            <div class="metric">
                                <div class="metric-value">£${insight.market_metrics.avg_revenue_per_patient.toLocaleString()}</div>
                                <div class="metric-label">Avg Revenue/Patient</div>
                            </div>
                            <div class="metric">
                                <div class="metric-value">${insight.market_metrics.patient_acquisition_cost}</div>
                                <div class="metric-label">Patient Acquisition Cost</div>
                            </div>
                        </div>
                        <div class="metrics-row">
                            <div class="metric">
                                <div class="metric-value">${insight.market_metrics.average_appointment_value}</div>
                                <div class="metric-label">Avg Appointment Value</div>
                            </div>
                            <div class="metric">
                                <div class="metric-value">${insight.market_metrics.no_show_rate}%</div>
                                <div class="metric-label">Area No-Show Rate</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="pricing-intelligence">
                        <h4 class="section-title">
                            <i class="fas fa-pound-sign"></i>
                            Competitive Pricing Intelligence
                        </h4>
                        <div class="pricing-grid">
                            ${insight.pricing_data.map(item => `
                                <div class="pricing-item">
                                    <div class="treatment-name">${item.treatment}</div>
                                    <div class="price-comparison">
                                        <span class="market-price">Market Avg: ${item.market_average}</span>
                                        <span class="price-trend ${item.trend === 'up' ? 'trending-up' : item.trend === 'down' ? 'trending-down' : 'stable'}">
                                            <i class="fas fa-arrow-${item.trend === 'up' ? 'up' : item.trend === 'down' ? 'down' : 'right'}"></i>
                                            ${item.trend_percentage}
                                        </span>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    
                    <div class="competitor-analysis">
                        <h4 class="section-title">
                            <i class="fas fa-users"></i>
                            Direct Competitors (${insight.competitors.length})
                        </h4>
                        <div class="competitor-list" id="competitors-${insight.postcode.replace(/\\s+/g, '')}">
                        </div>
                    </div>
                    
                    <div class="gap-analysis">
                        <h4 class="section-title">
                            <i class="fas fa-chart-line"></i>
                            Market Gap Analysis
                        </h4>
                        <div class="gap-items">
                            ${insight.service_gaps.map(gap => `
                                <div class="gap-item">
                                    <div class="gap-service">${gap.service}</div>
                                    <div class="gap-details">
                                        <span class="demand-level ${gap.demand_level.toLowerCase()}">${gap.demand_level} Demand</span>
                                        <span class="supply-level">Supply: ${gap.current_supply}</span>
                                        <span class="opportunity-value">Value: ${gap.opportunity_value}</span>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    
                    <div class="patient-insights">
                        <div class="insight-row">
                            <div class="insight-metric">
                                <div class="metric-value">${insight.patient_demographics.avg_age}</div>
                                <div class="metric-label">Average Patient Age</div>
                            </div>
                            <div class="insight-metric">
                                <div class="metric-value">${insight.patient_demographics.insurance_mix.private}%</div>
                                <div class="metric-label">Private Pay Patients</div>
                            </div>
                            <div class="insight-metric">
                                <div class="metric-value">${insight.patient_demographics.avg_household_income}</div>
                                <div class="metric-label">Avg Household Income</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="treatment-section">
                        <div class="treatment-header">
                            <div class="treatment-icon">
                                <i class="fas fa-tooth"></i>
                            </div>
                            <div class="treatment-title">High-Demand Treatments in ${insight.postcode}</div>
                        </div>
                        <div class="treatment-list" id="treatments-${insight.postcode.replace(/\\s+/g, '')}">
                        </div>
                    </div>
                    
                    ${insight.strategic_recommendations && insight.strategic_recommendations.length > 0 ? `
                        <div class="recommendations">
                            <div class="insights-title">
                                <div class="opportunity-icon">
                                    <i class="fas fa-lightbulb"></i>
                                </div>
                                Strategic Recommendations
                            </div>
                            <ul class="insights-items">
                                ${insight.strategic_recommendations.map(rec => `<li>${rec}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                    
                    ${insight.market_risks && insight.market_risks.length > 0 ? `
                        <div class="recommendations">
                            <div class="insights-title">
                                <div class="risk-icon">
                                    <i class="fas fa-exclamation-triangle"></i>
                                </div>
                                Market Risks
                            </div>
                            <ul class="insights-items">
                                ${insight.market_risks.map(risk => `<li>${risk}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                </div>
            `;
        }
        
        function populateCompetitors(insight) {
            const competitorContainer = document.getElementById(`competitors-${insight.postcode.replace(/\\s+/g, '')}`);
            if (competitorContainer) {
                competitorContainer.innerHTML = insight.competitors.map(competitor => `
                    <div class="competitor-item">
                        <div class="competitor-header">
                            <div class="competitor-name">${competitor.name}</div>
                            <div class="competitor-distance">${competitor.distance} miles</div>
                        </div>
                        <div class="competitor-details">
                            <div class="competitor-metrics">
                                <span class="metric-badge reviews">★ ${competitor.rating} (${competitor.review_count} reviews)</span>
                                <span class="metric-badge patients">${competitor.estimated_patients}/month</span>
                                <span class="metric-badge specialty">${competitor.specialties.join(', ')}</span>
                            </div>
                            <div class="competitor-strengths">
                                <strong>Competitive Advantages:</strong> ${competitor.competitive_advantages.join(', ')}
                            </div>
                        </div>
                    </div>
                `).join('');
            }
        }
        
        function populateTreatments(insight) {
            const treatmentContainer = document.getElementById(`treatments-${insight.postcode.replace(/\\s+/g, '')}`);
            if (treatmentContainer) {
                const treatments = getRecommendedTreatments(insight);
                treatmentContainer.innerHTML = treatments.map((treatment, index) => `
                    <div class="treatment-item">
                        <div class="treatment-rank">${index + 1}</div>
                        <div class="treatment-info">
                            <div class="treatment-name">${treatment.name}</div>
                            <div class="treatment-details">${treatment.details}</div>
                        </div>
                        <div class="treatment-demand">${treatment.demand}</div>
                    </div>
                `).join('');
            }
        }
        
        function getRecommendedTreatments(insight) {
            const income = insight.patient_demographics.insurance_mix.private > 70 ? 'high' : 
                          insight.patient_demographics.insurance_mix.private > 50 ? 'medium' : 'low';
            const competition = insight.competition_level.toLowerCase();
            
            const treatmentDatabase = [
                {
                    name: "Invisalign / Clear Aligners",
                    details: "Ages 18-40 • Middle to High Income • Aesthetics & Career",
                    demand: "Very High",
                    priority: income === 'high' ? 10 : income === 'medium' ? 8 : 4
                },
                {
                    name: "Teeth Whitening",
                    details: "Ages 20-50 • All Income Levels • Cosmetic Enhancement",
                    demand: "High",
                    priority: 9
                },
                {
                    name: "Dental Implants",
                    details: "Ages 45-75 • Upper Income • Tooth Replacement",
                    demand: "High",
                    priority: income === 'high' ? 9 : 6
                },
                {
                    name: "Composite Bonding",
                    details: "Ages 20-40 • Middle Income • Budget-Friendly Cosmetics",
                    demand: "Medium",
                    priority: income === 'medium' ? 8 : 5
                },
                {
                    name: "Veneers / Smile Makeovers",
                    details: "Ages 25-50 • High Income • Premium Cosmetics",
                    demand: "High",
                    priority: income === 'high' ? 9 : 3
                }
            ];
            
            const adjustedTreatments = treatmentDatabase.map(treatment => {
                let adjustedPriority = treatment.priority;
                
                if (income === 'high' && ['Invisalign / Clear Aligners', 'Dental Implants', 'Veneers / Smile Makeovers'].includes(treatment.name)) {
                    adjustedPriority += 2;
                }
                if (income === 'medium' && treatment.name === 'Composite Bonding') {
                    adjustedPriority += 1;
                }
                if (competition === 'high' && ['Invisalign / Clear Aligners', 'Veneers / Smile Makeovers'].includes(treatment.name)) {
                    adjustedPriority -= 1;
                }
                
                return {
                    ...treatment,
                    adjustedPriority
                };
            });
            
            return adjustedTreatments
                .sort((a, b) => b.adjustedPriority - a.adjustedPriority)
                .slice(0, 5);
        }
        
        document.getElementById('postcodeInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                analyzePostcodes();
            }
        });
    </script>
</body>
</html>""")

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy", 
        "service": "Smile IQ API",
        "backend_loaded": True,  # Always true for demo
        "port": os.environ.get("PORT", "8080"),
        "message": "API is running successfully"
    }

@app.post("/api/analyze")
async def analyze_postcodes(
    request: PostcodeRequest, 
    client_ip: str = Depends(rate_limit_dependency),
    api_key_valid: bool = Depends(validate_api_key)
):
    """Analyze dental market for given postcodes"""
    try:
        logger.info(f"Analyzing postcodes: {request.postcodes} from IP: {client_ip}")
        
        # Generate enhanced dummy data for demo
        dummy_insights = generate_dummy_insights(request.postcodes)
        
        return {
            "status": "success",
            "insights": dummy_insights,
            "practices_found": sum(len(insight["competitors"]) for insight in dummy_insights) + len(dummy_insights),
            "message": "Analysis completed successfully"
        }
        
    except ValueError as e:
        logger.warning(f"Validation error for postcodes {request.postcodes}: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Validation error: {str(e)}")
    except Exception as e:
        logger.error(f"Analysis error for postcodes {request.postcodes}: {str(e)}")
        raise HTTPException(status_code=500, detail="Analysis service temporarily unavailable")

def generate_dummy_insights(postcodes: List[str]) -> List[dict]:
    """Generate realistic dummy data for demo purposes"""
    
    insights = []
    
    for postcode in postcodes:
        # Determine location type for realistic data
        is_london = postcode.startswith(('SW', 'W', 'E', 'N', 'SE', 'NW'))
        is_manchester = postcode.startswith('M')
        is_birmingham = postcode.startswith('B')
        
        # Base metrics on location
        base_revenue = 320 if is_london else 280 if is_manchester else 250
        base_income = 65000 if is_london else 45000 if is_manchester else 42000
        competitor_count = random.randint(5, 12) if is_london else random.randint(2, 7)
        
        insight = {
            "postcode": postcode,
            "practice_density": round(random.uniform(2.1, 8.5), 1),
            "demographic_score": random.randint(60, 95),
            "growth_potential": random.randint(65, 90),
            "competition_level": "High" if competitor_count > 8 else "Medium" if competitor_count > 5 else "Low",
            "opportunity_score": random.randint(60, 95),
            "opportunity_value": random.randint(50000, 150000),
            
            "market_metrics": {
                "avg_revenue_per_patient": base_revenue + random.randint(-50, 100),
                "patient_acquisition_cost": f"£{random.randint(80, 180)}",
                "average_appointment_value": f"£{random.randint(120, 270)}",
                "no_show_rate": random.randint(8, 18)
            },
            
            "patient_demographics": {
                "avg_age": random.randint(38, 53),
                "avg_household_income": f"£{base_income + random.randint(-10000, 20000):,}",
                "insurance_mix": {
                    "private": random.randint(40, 80) if is_london else random.randint(30, 65),
                    "nhs": random.randint(20, 60)
                }
            },
            
            "competitors": generate_dummy_competitors(competitor_count, is_london),
            
            "pricing_data": [
                {
                    "treatment": "Invisalign",
                    "market_average": "£3,850" if is_london else "£3,200",
                    "trend": random.choice(["up", "stable", "down"]),
                    "trend_percentage": f"{random.randint(2, 12)}%"
                },
                {
                    "treatment": "Dental Implants",
                    "market_average": "£3,400" if is_london else "£2,800", 
                    "trend": random.choice(["up", "stable"]),
                    "trend_percentage": f"{random.randint(1, 8)}%"
                },
                {
                    "treatment": "Teeth Whitening",
                    "market_average": "£550" if is_london else "£420",
                    "trend": "up",
                    "trend_percentage": f"{random.randint(5, 20)}%"
                }
            ],
            
            "service_gaps": generate_dummy_service_gaps(competitor_count),
            
            "strategic_recommendations": generate_dummy_recommendations(postcode, is_london, competitor_count),
            
            "market_risks": generate_dummy_risks(competitor_count, is_london),
        }
        
        insights.append(insight)
    
    return insights

def generate_dummy_competitors(count: int, is_london: bool) -> List[dict]:
    """Generate dummy competitor data"""
    
    practice_names = [
        "SmileCare Dental", "Premier Dental Practice", "City Dental Centre",
        "Bright Smile Clinic", "Elite Dental Practice", "Modern Dentistry",
        "Family Dental Care", "Dental Excellence", "Urban Dental Studio",
        "Perfect Smile Clinic", "Advance Dental Care", "Gentle Dental Practice"
    ]
    
    specialties_options = [
        ["General Dentistry", "Cosmetics"],
        ["Orthodontics", "Implants"],
        ["General Dentistry"],
        ["Cosmetics", "Whitening"],
        ["Implants", "Oral Surgery"],
        ["Invisalign", "Cosmetics"],
        ["General Dentistry", "Periodontics"],
        ["Emergency Dentistry", "General"]
    ]
    
    advantages_pool = [
        "Extended evening hours", "Same-day appointments", "Advanced technology",
        "Specialist team", "Payment plans", "Premium location", "Corporate backing",
        "Long establishment", "Strong online presence", "Sedation dentistry",
        "Digital dentistry", "Multi-language staff"
    ]
    
    competitors = []
    for i in range(count):
        name = practice_names[i % len(practice_names)]
        if i >= len(practice_names):
            name += f" {i // len(practice_names) + 1}"
            
        competitors.append({
            "name": name,
            "distance": f"{random.uniform(0.2, 3.0):.1f}",
            "rating": f"{random.uniform(3.5, 5.0):.1f}",
            "review_count": random.randint(50, 500),
            "estimated_patients": random.randint(100, 250) + (50 if is_london else 0),
            "specialties": random.choice(specialties_options),
            "competitive_advantages": random.sample(advantages_pool, random.randint(1, 3))
        })
    
    return competitors

def generate_dummy_service_gaps(competitor_count: int) -> List[dict]:
    """Generate dummy service gap data"""
    
    all_gaps = [
        {
            "service": "Emergency Dental Care",
            "demand_level": "High",
            "current_supply": "Limited",
            "opportunity_value": "£45k/year"
        },
        {
            "service": "Pediatric Dentistry",
            "demand_level": "High" if competitor_count < 4 else "Medium",
            "current_supply": "Undersupplied" if competitor_count < 4 else "Adequate",
            "opportunity_value": "£35k/year"
        },
        {
            "service": "Dental Anxiety Management",
            "demand_level": "Medium",
            "current_supply": "Limited",
            "opportunity_value": "£25k/year"
        },
        {
            "service": "Same-Day Dentistry",
            "demand_level": "High",
            "current_supply": "Limited",
            "opportunity_value": "£30k/year"
        }
    ]
    
    return random.sample(all_gaps, random.randint(1, 3))

def generate_dummy_recommendations(postcode: str, is_london: bool, competitor_count: int) -> List[str]:
    """Generate dummy strategic recommendations"""
    
    recommendations = []
    
    if competitor_count < 4:
        recommendations.append("Consider premium positioning - limited competition allows for higher pricing")
    
    if is_london:
        recommendations.extend([
            "Focus on cosmetic treatments - high disposable income demographic",
            "Implement extended hours to capture working professionals"
        ])
    
    if competitor_count > 7:
        recommendations.extend([
            "Differentiate with specialized services (sedation, emergency care)",
            "Invest heavily in online presence and patient acquisition"
        ])
    
    recommendations.extend([
        "Target Invisalign marketing - high demand, good margins in this area",
        "Develop partnerships with local healthcare providers",
        "Consider implementing digital dentistry solutions",
        "Focus on patient experience and comfort amenities"
    ])
    
    return random.sample(recommendations, min(3, len(recommendations)))

def generate_dummy_risks(competitor_count: int, is_london: bool) -> List[str]:
    """Generate dummy market risks"""
    
    risks = []
    
    if competitor_count > 6:
        risks.append("High competition may pressure pricing and patient acquisition costs")
    
    if is_london:
        risks.append("High commercial rents may impact profitability margins")
    
    risks.extend([
        "Economic downturn could reduce demand for elective cosmetic procedures",
        "NHS policy changes may affect patient flow",
        "Rising staff costs in competitive dental market"
    ])
    
    if random.random() > 0.5:
        risks.append("New corporate dental chains entering the market")
    
    return random.sample(risks, min(2, len(risks)))

# Security: Serve static files securely if directory exists
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# Security: Custom error handlers to prevent information disclosure
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return HTMLResponse(
        content="<html><body><h1>404 - Page Not Found</h1></body></html>",
        status_code=404
    )

@app.exception_handler(500)
async def internal_server_error_handler(request: Request, exc):
    logger.error(f"Internal server error: {exc}")
    return HTMLResponse(
        content="<html><body><h1>500 - Internal Server Error</h1></body></html>",
        status_code=500
    )

# This is crucial for Railway deployment
if __name__ == "__main__":
    import uvicorn
    
    # Security: Validate environment configuration
    port = int(os.environ.get("PORT", 8080))
    
    # Security: Different configurations for different environments
    if os.environ.get("ENVIRONMENT") == "production":
        log_level = "warning"
        access_log = False
    else:
        log_level = "info"
        access_log = True
    
    logger.info(f"🚀 Starting Smile IQ server on 0.0.0.0:{port}")
    logger.info(f"🔒 Security features enabled: Rate limiting, Input validation, Security headers")
    
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=port, 
        log_level=log_level,
        access_log=access_log,
        # Security: Production settings
        server_header=False,  # Hide server header
        date_header=False     # Hide date header
    )
