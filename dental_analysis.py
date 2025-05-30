import asyncio
import random
from datetime import datetime
from typing import List, Dict, Any

class DentalMarketAPI:
    """Dental Market Analysis API - Mock implementation for frontend testing"""
    
    def __init__(self):
        """Initialize the API"""
        pass
    
    async def analyze_postcodes(self, postcodes: List[str]) -> Dict[str, Any]:
        """
        Analyze dental market for given postcodes
        Returns mock data for frontend testing
        """
        insights = []
        
        for postcode in postcodes:
            insight = {
                "postcode": postcode.upper(),
                "practice_density": round(random.uniform(1.2, 8.5), 1),
                "competition_level": random.choice(["Low", "Medium", "High"]),
                "demographic_score": random.randint(45, 95),
                "growth_potential": random.randint(35, 90),
                "predicted_demand": random.choice(["Growing", "Stable", "Declining"]),
                "risk_factors": random.sample([
                    "High competition", 
                    "Economic uncertainty", 
                    "Aging population",
                    "Limited parking",
                    "High rent costs"
                ], k=random.randint(1, 3)),
                "opportunities": random.sample([
                    "Underserved elderly population",
                    "Growing young families", 
                    "Premium service gap",
                    "Cosmetic demand rising",
                    "Insurance coverage improving"
                ], k=random.randint(2, 4))
            }
            insights.append(insight)
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "postcodes_analyzed": len(postcodes),
            "practices_found": len(postcodes) * random.randint(2, 6),
            "insights": insights
        }
    
    def get_postcode_summary(self, postcode: str) -> Dict[str, Any]:
        """
        Get detailed summary for specific postcode
        Returns mock data for frontend testing
        """
        return {
            "postcode": postcode.upper(),
            "summary": f"Mock summary for {postcode}",
            "total_practices": random.randint(5, 25),
            "market_opportunity": random.choice(["Excellent", "Good", "Fair", "Poor"])
        }
