FROM python:3.11-alpine
RUN apk add --no-cache openssl openssh
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY . .
RUN chmod +x run.sh
CMD ["./run.sh"]
