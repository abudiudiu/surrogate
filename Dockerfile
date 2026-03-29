FROM python:3.12-alpine

# uvloop needs a C compiler on Alpine; musl-dev provides it
RUN apk add --no-cache gcc musl-dev && \
    pip install --no-cache-dir uvloop && \
    apk del gcc musl-dev

RUN mkdir -p /var/lib/proxy

COPY proxy.py /app/proxy.py

EXPOSE 3128

CMD ["python3", "/app/proxy.py"]
