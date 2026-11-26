FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY app ./app
COPY sensor ./sensor
COPY tools ./tools
COPY feature_order.json ./
COPY label_map.json ./

# Every target architecture must load and run a v2 tree bundle before publishing. The production bundle is
# private and staged on the node (NIDS_V2_MODEL_DIR), so this builds a throwaway one.
RUN python -m tools.smoke_model

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
