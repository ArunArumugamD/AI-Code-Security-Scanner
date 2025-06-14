# run_api.py
import uvicorn

if __name__ == "__main__":
    print("🚀 Starting AISec Scanner API...")
    print("📚 API Documentation: http://localhost:8000/docs")
    print("🔧 Alternative docs: http://localhost:8000/redoc")
    print("--------------------------------------------")
    
    # Use import string format for reload to work
    uvicorn.run(
        "src.api.main:app",  # Changed to string format
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
