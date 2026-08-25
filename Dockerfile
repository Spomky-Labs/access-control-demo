# A single container that serves the demo, so that trying it out takes no PHP, no Composer and
# no Symfony CLI on the host.
#
# There is no database service anywhere in this project: the accounts and the documents are in
# memory, which is the point — what is being demonstrated is authorization, not persistence.
FROM dunglas/frankenphp:1-php8.4-alpine

ENV SERVER_NAME=:8000
ENV APP_ENV=dev

RUN install-php-extensions ctype iconv opcache zip

COPY --from=composer/composer:2-bin /composer /usr/bin/composer

WORKDIR /app

# Dependencies first, so editing the application does not re-resolve them on every build.
COPY composer.json composer.lock symfony.lock ./
RUN composer install --no-interaction --no-progress --no-scripts --no-autoloader

COPY . .
RUN composer dump-autoload --optimize \
 && composer run-script post-install-cmd

EXPOSE 8000

# Plain HTTP: frankenphp only turns on TLS when --domain is given, and the certificate is the
# host's business anyway — a reverse proxy in production, nothing at all on a laptop.
CMD ["frankenphp", "php-server", "--root", "public/", "--listen", ":8000"]
