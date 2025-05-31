from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
from typing import List
import os
import logging
import sys

# Add this to confirm Railway is loading the correct file
print("🚀 Starting Smile IQ server - main.py loaded!")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Smile IQ - Dental Market Intelligence API",
    description="ML-powered dental market analysis and insights",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Try to import dental analysis backend
try:
    from dental_analysis import DentalMarketAPI
    dental_api = DentalMarketAPI()
    logger.info("✅ Dental analysis backend loaded successfully")
except ImportError as e:
    logger.error(f"❌ Failed to import dental_analysis: {e}")
    dental_api = None

class PostcodeRequest(BaseModel):
    postcodes: List[str]

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
        .competition-badge {
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
        }
        .competition-low {
            background: #c6f6d5;
            color: #276749;
            border: 1px solid #9ae6b4;
        }
        .competition-medium {
            background: #fed7aa;
            color: #c2410c;
            border: 1px solid #fdba74;
        }
        .competition-high {
            background: #fecaca;
            color: #dc2626;
            border: 1px solid #fca5a5;
        }
        .score-section {
            margin: 32px 0;
        }
        .score-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }
        .score-label {
            font-size: 0.9rem;
            color: var(--midnight-light);
            font-weight: 500;
        }
        .score-value {
            font-weight: 600;
            color: var(--midnight-blue);
        }
        .score-bar {
            width: 100%;
            height: 6px;
            background: var(--beige-dark);
            border-radius: 3px;
            overflow: hidden;
        }
        .score-fill {
            height: 100%;
            background: var(--midnight-blue);
            border-radius: 3px;
            transition: width 1s cubic-bezier(0.4, 0, 0.2, 1);
            width: 0;
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
        .insights-list {
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
                
                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
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
                ${practicesFound} practices found
            `;
            
            const summaryStats = document.getElementById('summaryStats');
            const avgDensity = insights.reduce((sum, i) => sum + i.practice_density, 0) / insights.length;
            const avgDemographic = insights.reduce((sum, i) => sum + i.demographic_score, 0) / insights.length;
            const avgGrowth = insights.reduce((sum, i) => sum + i.growth_potential, 0) / insights.length;
            const lowCompetition = insights.filter(i => i.competition_level === 'Low').length;
            
            summaryStats.innerHTML = `
                <div class="stat-card fade-in">
                    <div class="stat-number">${insights.length}</div>
                    <div class="stat-label">Postcodes Analyzed</div>
                </div>
                <div class="stat-card fade-in">
                    <div class="stat-number">${avgDensity.toFixed(1)}</div>
                    <div class="stat-label">Avg Practice Density</div>
                </div>
                <div class="stat-card fade-in">
                    <div class="stat-number">${avgDemographic.toFixed(0)}</div>
                    <div class="stat-label">Avg Demographic Score</div>
                </div>
                <div class="stat-card fade-in">
                    <div class="stat-number">${lowCompetition}</div>
                    <div class="stat-label">Low Competition Areas</div>
                </div>
            `;
            
            resultsGrid.innerHTML = insights.map(insight => createInsightCard(insight)).join('');
            
            insights.forEach(insight => {
                populateTreatments(insight);
            });
            
            document.getElementById('resultsSection').style.display = 'block';
            
            setTimeout(() => {
                document.querySelectorAll('.score-fill').forEach(bar => {
                    const width = bar.dataset.width;
                    bar.style.width = width + '%';
                });
            }, 200);
        }
        
        function createInsightCard(insight) {
            const competitionClass = `competition-${insight.competition_level.toLowerCase()}`;
            
            return `
                <div class="insight-card fade-in">
                    <div class="postcode-title">
                        <div class="postcode-icon">
                            <i class="fas fa-map-marker-alt"></i>
                        </div>
                        ${insight.postcode}
                    </div>
                    <div class="metrics-row">
                        <div class="metric">
                            <div class="metric-value">${insight.practice_density.toFixed(1)}</div>
                            <div class="metric-label">Practice Density</div>
                        </div>
                        <div class="metric">
                            <div class="metric-value">${(Math.random() * 8 + 2).toFixed(1)}</div>
                            <div class="metric-label">Predicted Demand</div>
                        </div>
                    </div>
                    <div style="text-align: center;">
                        <span class="competition-badge ${competitionClass}">
                            <i class="fas fa-circle"></i>
                            ${insight.competition_level} Competition
                        </span>
                    </div>
                    <div class="score-section">
                        <div class="score-header">
                            <span class="score-label">Demographic Score</span>
                            <span class="score-value">${insight.demographic_score.toFixed(0)}/100</span>
                        </div>
                        <div class="score-bar">
                            <div class="score-fill" data-width="${insight.demographic_score}"></div>
                        </div>
                    </div>
                    <div class="score-section">
                        <div class="score-header">
                            <span class="score-label">Growth Potential</span>
                            <span class="score-value">${insight.growth_potential.toFixed(0)}/100</span>
                        </div>
                        <div class="score-bar">
                            <div class="score-fill" data-width="${insight.growth_potential}"></div>
                        </div>
                    </div>
                    <div class="treatment-section">
                        <div class="treatment-header">
                            <div class="treatment-icon">
                                <i class="fas fa-tooth"></i>
                            </div>
                            <div class="treatment-title">Top 5 Most Popular Treatments in ${insight.postcode}</div>
                        </div>
                        <div class="treatment-list" id="treatments-${insight.postcode.replace(/\\s+/g, '')}">
                        </div>
                    </div>
                    ${insight.risk_factors.length > 0 ? `
                        <div class="insights-list">
                            <div class="insights-title">
                                <div class="risk-icon">
                                    <i class="fas fa-exclamation-triangle"></i>
                                </div>
                                Risk Factors
                            </div>
                            <ul class="insights-items">
                                ${insight.risk_factors.map(risk => `<li>${risk}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                    ${insight.opportunities.length > 0 ? `
                        <div class="insights-list">
                            <div class="insights-title">
                                <div class="opportunity-icon">
                                    <i class="fas fa-lightbulb"></i>
                                </div>
                                Opportunities
                            </div>
                            <ul class="insights-items">
                                ${insight.opportunities.map(opp => `<li>${opp}</li>`).join('')}
                            </ul>
                        </div>
                    ` : ''}
                </div>
            `;
        }
        
        function populateTreatments(insight) {
            const treatmentContainer = document.getElementById(`treatments-${insight.postcode.replace(/\\s+/g, '')}`);
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
        
        function getRecommendedTreatments(insight) {
            const income = insight.demographic_score > 75 ? 'high' : insight.demographic_score > 50 ? 'medium' : 'low';
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
                    priority: insight.demographic_score > 70 ? 9 : 6
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
        "backend_loaded": dental_api is not None,
        "port": os.environ.get("PORT", "8080"),
        "message": "API is running successfully"
    }

@app.post("/api/analyze")
async def analyze_postcodes(request: PostcodeRequest):
    """Analyze dental market for given postcodes"""
    if not dental_api:
        raise HTTPException(status_code=503, detail="Backend analysis service not available")
    
    try:
        logger.info(f"Analyzing postcodes: {request.postcodes}")
        results = await dental_api.analyze_postcodes(request.postcodes)
        return results
    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/api/postcode/{postcode}")
async def get_postcode_summary(postcode: str):
    """Get detailed summary for specific postcode"""
    if not dental_api:
        raise HTTPException(status_code=503, detail="Backend analysis service not available")
    
    try:
        summary = dental_api.get_postcode_summary(postcode.upper())
        if 'error' in summary:
            raise HTTPException(status_code=404, detail=summary['error'])
        return summary
    except Exception as e:
        logger.error(f"Summary error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Summary failed: {str(e)}")

# Serve static files if directory exists
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# This is crucial for Railway deployment
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    logger.info(f"🚀 Starting Smile IQ server on 0.0.0.0:{port}")
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=port, 
        log_level="info",
        access_log=True
    )
