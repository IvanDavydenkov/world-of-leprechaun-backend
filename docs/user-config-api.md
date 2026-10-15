# Конфиги пользователя

Требуется сессионная cookie после Yandex OAuth. user_id не передаётся: владелец определяется по сессии, включая admin.

## Список
GET /me/configs

Ответ 200 — массив собственных active конфигов. Без конфигов: []. Пример:
```json
[{"id":"config-id","name":"Phone","status":"active","version":1,"created_at":"2026-10-15T12:00:00Z","download_available":true,"download_url":"/me/configs/config-id/download"}]
```
Удалённые и незавершённые записи скрыты. Если файла нет, download_available=false и download_url=null. Неполадки хранилища возвращают 503.

## Скачивание
GET /me/configs/{config_id}/download

Ответ 200 — файл .conf, Content-Type: application/octet-stream, Content-Disposition: attachment; filename=config-<id>.conf. Можно использовать ссылку на download_url; при fetch с другого origin требуется credentials: include и согласованная настройка прокси/cookie.

401 — нет действующей сессии. 404 — отсутствующий, чужой, неактивный конфиг или отсутствующий файл. 503 — недоступность внутреннего сервиса, хранилища или ошибка расшифровки. Ответы не кэшируются (Cache-Control: no-store).

Оба маршрута опубликованы на users (:8080). Аналогичные внутренние маршруты VPN-сервиса требуют X-Service-Token; X-Actor-ID заполняется users на основании проверенной сессии. У admin нет исключения для скачивания чужого файла через /me. SSH при скачивании не используется. VPN-конфиги на сервере эти запросы не меняют.