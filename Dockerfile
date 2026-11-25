FROM python:3.12-slim
WORKDIR /app

COPY requirements-firewall.txt .
RUN pip install --no-cache-dir -r requirements-firewall.txt

COPY firewall/ firewall/
COPY policies/ policies/
COPY ml/ ml/

# Train the lightweight classifier inside the image: seconds, deterministic, and it is guaranteed to be
# built with the same scikit-learn version that loads it.
RUN python ml/make_training_data.py && python ml/train_light.py && rm -rf data/*.jsonl

ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "--app-dir", "firewall", "main:app", "--host", "0.0.0.0", "--port", "8000"]