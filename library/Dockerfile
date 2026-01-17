FROM python:3.10-slim

WORKDIR /

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

VOLUME ["/audio"]

EXPOSE 2000

CMD ["python", "library.py"]

