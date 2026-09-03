FROM python:3.12-slim

WORKDIR /lab
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY tapolab ./tapolab
COPY config ./config
COPY main.py .

CMD ["python", "main.py", "--help"]
