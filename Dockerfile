FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY app ./app
COPY sensor ./sensor
COPY meta.json ./
COPY config.json ./
COPY feature_order.json ./
COPY label_map.json ./
COPY label_encoder.joblib ./
COPY scaler.joblib ./
COPY cicids2018_dense_model.keras ./

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
