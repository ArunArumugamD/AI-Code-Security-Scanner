# AISec Scanner - Advanced AI-Powered Code Security Scanner

## Overview
Enterprise-grade code security scanner combining Graph Neural Networks and CodeBERT for unprecedented vulnerability detection accuracy.

## Key Features
- **Multi-Language Support**: Python, JavaScript, Java, PHP, C/C++
- **AI-Powered**: GNN + CodeBERT hybrid model with confidence scoring
- **Real-Time**: WebSocket-based live scanning as you code
- **Intelligence**: CVE feed integration with zero-day pattern detection
- **Enterprise Ready**: Docker/Kubernetes deployment with horizontal scaling

## Architecture
- **Core Engine**: Modular analyzer system with plugin architecture
- **AI Layer**: Transformer-based embeddings + Graph Neural Networks
- **Data Layer**: PostgreSQL for persistence, Redis for caching
- **API Layer**: FastAPI with WebSocket support
- **UI Layer**: React with real-time dashboard

## Getting Started
1. Install dependencies: pip install -r requirements.txt
2. Configure database: Update .env file
3. Run migrations: lembic upgrade head
4. Start server: uvicorn src.api.main:app --reload

## Why This Stands Out
- **Hybrid AI Approach**: Combines structural (GNN) and semantic (CodeBERT) analysis
- **Self-Learning**: Improves accuracy from user feedback
- **Live Analysis**: Instant feedback while coding
- **Comprehensive**: Covers OWASP Top 10, CWE Top 25, and custom patterns
