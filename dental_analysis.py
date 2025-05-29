# IMPORTANT: Remove or comment out this entire section at the bottom of your dental_analysis.py file:

# # Example usage and testing
# async def main():
#     """Example usage of the dental market analysis system"""
#     api = DentalMarketAPI()
#     
#     # Test postcodes
#     test_postcodes = ['SW1A 1AA', 'M1 1AA', 'B1 1AA', 'LS1 1AA', 'G1 1AA']
#     
#     # Run analysis
#     results = await api.analyze_postcodes(test_postcodes)
#     
#     print("=== DENTAL MARKET ANALYSIS RESULTS ===")
#     print(f"Analysis completed at: {results['timestamp']}")
#     print(f"Postcodes analyzed: {results['postcodes_analyzed']}")
#     print(f"Practices found: {results['practices_found']}")
#     print()
#     
#     for insight in results['insights']:
#         print(f"POSTCODE: {insight['postcode']}")
#         print(f"  Practice Density: {insight['practice_density']} per 1000 residents")
#         print(f"  Competition Level: {insight['competition_level']}")
#         print(f"  Demographic Score: {insight['demographic_score']}/100")
#         print(f"  Growth Potential: {insight['growth_potential']}/100")
#         print(f"  Predicted Demand: {insight['predicted_demand']}")
#         print(f"  Risk Factors: {', '.join(insight['risk_factors'])}")
#         print(f"  Opportunities: {', '.join(insight['opportunities'])}")
#         print("-" * 50)

# if __name__ == "__main__":
#     asyncio.run(main())

# ^^^ REMOVE OR COMMENT OUT EVERYTHING ABOVE ^^^
