#!/bin/bash

# Настройка API ключа vulnx
if [ ! -z "$VULNX_API_KEY" ]; then
    echo "Configuring vulnx API key..."
    mkdir -p /root/.config/vulnx/
    cat > /root/.config/vulnx/config.yaml << EOF
api-key: $VULNX_API_KEY
disable-update-check: true
EOF
    echo "✓ Vulnx configured with API key"
fi

# Создаем software.txt если его нет
if [ ! -f "/app/software.txt" ]; then
    echo "Creating empty software.txt..."
    touch /app/software.txt
    echo "✓ Empty software.txt created. Please upload your software list through the web interface."
fi

# Функция для получения SSL сертификата
get_ssl_certificate() {
    if [ ! -z "$DOMAIN" ]; then
        echo "Checking SSL certificate for $DOMAIN..."
        
        if [ ! -d "/etc/letsencrypt/live/$DOMAIN" ]; then
            echo "Obtaining SSL certificate for $DOMAIN..."
            certbot certonly --standalone \
                -d $DOMAIN \
                --non-interactive \
                --agree-tos \
                -m $EMAIL \
                --http-01-port 8888 || {
                    echo "⚠ Failed to obtain SSL certificate, continuing with HTTP only"
                    return 1
                }
            echo "✓ SSL certificate obtained"
        else
            echo "✓ SSL certificate exists"
            # Продлеваем если нужно
            certbot renew --non-interactive --quiet
        fi
        
        # Создаем симлинки
        mkdir -p /app/ssl
        ln -sf /etc/letsencrypt/live/$DOMAIN/fullchain.pem /app/ssl/cert.pem
        ln -sf /etc/letsencrypt/live/$DOMAIN/privkey.pem /app/ssl/key.pem
        
        return 0
    fi
    return 1
}

# Пытаемся получить SSL сертификат
get_ssl_certificate
SSL_STATUS=$?

# Запускаем приложение
echo "Starting vulnerability manager..."
if [ $SSL_STATUS -eq 0 ] && [ -f /app/ssl/cert.pem ] && [ -f /app/ssl/key.pem ]; then
    echo "✓ HTTPS enabled for $DOMAIN"
    exec python app.py --ssl
else
    echo "⚠ HTTPS not enabled, running in HTTP mode"
    echo "ℹ To enable HTTPS, set DOMAIN and EMAIL in .env file"
    exec python app.py
fi

