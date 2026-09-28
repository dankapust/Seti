FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code, tests and demo scripts
COPY src/ ./src/
COPY config/ ./config/
COPY tests/ ./tests/
COPY demo_stage1.py ./
COPY demo_stage2.py ./

ENV PYTHONPATH=/app

CMD ["python", "-m", "pytest", "tests/test_framing.py", "-v"]