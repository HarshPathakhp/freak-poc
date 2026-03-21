FROM ubuntu:14.04

RUN apt-get update && apt-get install -y \
    apache2 \
    libapache2-mod-ssl \
    openssl

# Enable SSL module
RUN a2enmod ssl

# Generate self-signed cert
RUN mkdir -p /etc/ssl/localcerts && \
    openssl req -x509 -newkey rsa:2048 \
    -keyout /etc/ssl/localcerts/selfsigned.key \
    -out /etc/ssl/localcerts/selfsigned.crt \
    -days 365 -nodes \
    -subj "/CN=localhost"

# Copy your apache config
COPY apache-freak.conf /etc/apache2/sites-available/default-ssl.conf

RUN a2ensite default-ssl

EXPOSE 443

CMD ["apache2ctl", "-D", "FOREGROUND"]