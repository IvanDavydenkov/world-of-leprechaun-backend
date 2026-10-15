# Production: frontend и API на отдельных доменах

Публичные адреса: https://worldofleprechauns.ru и https://api.worldofleprechauns.ru. Оба обслуживает host Nginx на сервере приложения. VPN-хост может быть отдельным. DNS A/AAAA направьте на сервер приложения; этот шаблон не меняет DNS.

## Backend
Скопируйте deploy/production.env.example в .env.production на сервере (файл игнорируется Git). Заполните секреты. Сохраните имеющийся VPN_CONFIG_ENCRYPTION_KEY при переносе существующей БД: его замена лишит доступа к конфигам и паролям серверов. MongoDB-пароли для URI используйте случайные hex, как в локальном генераторе, чтобы не требовалось URL-кодирование. Скопируйте проверенный публичный ключ хоста в secrets/vpn_known_hosts, доступный для чтения nonroot-контейнеру; директория 0755 и публичный файл 0644 достаточны.

```dotenv
FRONTEND_ORIGIN=https://worldofleprechauns.ru
YANDEX_REDIRECT_URL=https://api.worldofleprechauns.ru/auth/yandex/callback
AUTH_SUCCESS_REDIRECT_URL=https://worldofleprechauns.ru/
AUTH_LOGOUT_REDIRECT_URL=https://worldofleprechauns.ru/
VPN_KNOWN_HOSTS_FILE=/run/secrets/vpn_known_hosts
```

Эти значения передаются через Compose. INTERNAL_SERVICE_TOKEN и ключ шифрования заполните вместе с Yandex и MongoDB. Старые SSH env пока нужны для выдачи: реестр серверов ещё не выбирает рабочий хост.

```bash
docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml config --quiet
docker compose --env-file .env.production -f compose.yaml -f compose.production.yaml up -d --build
```

MongoDB не публикует порт. users публикуется только на 127.0.0.1:8080. VPN API остаётся внутренним, порт 8081 привязан к loopback и не проксируется публично. Имя Docker network определяет каталог/Compose project name; укажите его в BACKEND_NETWORK фронта.

## Frontend
Проект: C:/Users/hazam/WebstormProjects/moyato-vpn. production.env.example содержит VITE_API_ORIGIN=https://api.worldofleprechauns.ru, HTTP_BIND_ADDRESS=127.0.0.1, HTTP_PORT=8082. VITE_API_ORIGIN — публичная переменная этапа сборки; после изменения нужна пересборка, секреты в VITE_* не помещаются. Frontend Compose передаёт значение как build arg. Запросы RTK Query используют credentials: include; вход — навигация на API /auth/yandex/login.

## Yandex OAuth
В настройках приложения зарегистрируйте точный production Redirect URI: https://api.worldofleprechauns.ru/auth/yandex/callback. Для локальной разработки сохраните http://localhost:8080/auth/yandex/callback. Хост страницы кнопки — https://worldofleprechauns.ru. Client Secret остаётся только в backend.

## Nginx и HTTPS
Шаблон: deploy/nginx/worldofleprechauns.conf. Host Nginx проксирует frontend на 127.0.0.1:8082, API на 127.0.0.1:8080; /internal запрещён. Сертификат должен включать оба домена. Пути в шаблоне рассчитаны на один SAN-сертификат, именованный worldofleprechauns.ru. Сначала получите сертификат (HTTP challenge/webroot), затем включайте HTTPS server blocks. Проверить nginx -t перед reload. В этой Windows-среде Docker и Nginx не установлены: runtime-конфигурация контейнеров и TLS здесь не проверялась.

CORS выставляет backend, не дублируйте эти заголовки в Nginx. Разрешён ровно FRONTEND_ORIGIN, credentials=true, методы GET/POST/PATCH/PUT/DELETE, заголовки Content-Type/Idempotency-Key. Чужой Origin получает 403. Preflight не требует сессии. Content-Disposition доступен браузерному клиенту.

Сессионная cookie host-only на API, HttpOnly, Secure на HTTPS, SameSite=Lax. Оба production-домена принадлежат одному site. Не задавайте Domain=.worldofleprechauns.ru и не ослабляйте SameSite для этой схемы. Backend определяет Secure по YANDEX_REDIRECT_URL, а не недоверенному X-Forwarded-Proto.

## Localhost
Локальный .env не заменяется production-шаблоном. FRONTEND_ORIGIN=http://localhost:5173, YANDEX_REDIRECT_URL=http://localhost:8080/auth/yandex/callback. Оставьте AUTH_SUCCESS_REDIRECT_URL/AUTH_LOGOUT_REDIRECT_URL пустыми для существующего Vite OAuth proxy, либо задайте http://localhost:5173/. В frontend VITE_API_ORIGIN пустой: Vite proxy передаёт API на 127.0.0.1:8080, включая /admin/vpn-servers. Используйте localhost последовательно, не смешивая его с 127.0.0.1 в браузере.

Logout из RTK Query передаёт Accept: application/json и получает 204 с удалённой cookie, без fetch-редиректа на другой origin. Обычный form logout сохраняет 303 на AUTH_LOGOUT_REDIRECT_URL.