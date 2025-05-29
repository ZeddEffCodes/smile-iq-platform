
import os
from fastapi import FastAPI
import uvicorn

print("🚀 Starting simple test app...")

app = FastAPI()

@app.get("/")
def read_root():
    print("📍 Root endpoint called")
    return {"message": "SUCCESS! Railway is working!", "status": "live"}

@app.get("/test")
def test():
    return {"test": "working", "port": os.environ.get("PORT", "8000")}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"🌐 Attempting to start server on 0.0.0.0:{port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
