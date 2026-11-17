# syntax=docker/dockerfile:1

# Stage 1: only the Composer autoloader (the app has no runtime packages).
FROM composer:2 AS vendor
WORKDIR /app
COPY composer.json composer.lock ./
COPY src ./src
RUN composer install --no-dev --no-interaction --no-progress --classmap-authoritative --ignore-platform-reqs

# Stage 2: Apache + mod_php, unprivileged, no access log.
FROM php:8.3-apache-bookworm

RUN docker-php-ext-enable opcache \
    && a2disconf other-vhosts-access-log \
    && sed -ri 's/^Listen 80$/Listen 8080/' /etc/apache2/ports.conf \
    && mkdir -p /app/var \
    && chown www-data:www-data /app/var

COPY docker/apache.conf /etc/apache2/sites-available/000-default.conf
COPY docker/php.ini /usr/local/etc/php/conf.d/zz-hush.ini
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/hush-entrypoint

WORKDIR /app
COPY --from=vendor /app/vendor ./vendor
COPY composer.json ./
COPY bin ./bin
COPY migrations ./migrations
COPY public ./public
COPY resources ./resources
COPY src ./src

ENV HUSH_DB_PATH=/app/var/hush.sqlite
USER www-data
EXPOSE 8080
VOLUME ["/app/var"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD php -r 'exit(@file_get_contents("http://127.0.0.1:8080/healthz") === false ? 1 : 0);'

ENTRYPOINT ["hush-entrypoint"]
CMD ["apache2-foreground"]
