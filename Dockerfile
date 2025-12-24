FROM python:3-alpine
ENV PYTHONUNBUFFERED=1
WORKDIR /app
RUN apk add --no-cache python3-dev py3-pip
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "app.py"]