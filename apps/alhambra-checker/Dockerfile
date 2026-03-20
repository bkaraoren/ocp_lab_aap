FROM mcr.microsoft.com/playwright/python:v1.51.0-noble

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY checker.py .

RUN chmod -R g+rwx /app /tmp

CMD ["python3", "checker.py"]
