FROM ubuntu:14.04

RUN mkdir /freak && \
    openssl genrsa -out /freak/server_key.pem 2048 && \
    openssl req -new -x509 \
      -key /freak/server_key.pem \
      -out /freak/server_cert.pem \
      -days 3650 \
      -subj "/CN=freak-demo"

WORKDIR /freak
CMD ["bash"]      