# Выдача и отзыв конфигов через API

Публичный API находится на users (`http://localhost:8080` локально). Все маршруты требуют сессионную cookie и актуальную роль admin. Запросы изменения требуют Origin, совпадающий с FRONTEND_ORIGIN, а если эта настройка пустая — с origin YANDEX_REDIRECT_URL. Заголовок role или X-Actor-ID от браузера не даёт полномочий.

## Создать именно новые конфиги

```http
POST /admin/users/{user_id}/configs
Content-Type: application/json
Origin: http://localhost:8080
Idempotency-Key: issue-phone-and-laptop-1

{"count": 2}
```

count — целое 1..20. Это размер пачки, а не лимит на пользователя. Создаются новые записи и ключи; удалённые или неназначенные конфиги не используются вместо них.

## Отозвать

Один:

```http
DELETE /admin/users/{user_id}/configs/{config_id}
Origin: http://localhost:8080
Idempotency-Key: revoke-one-1
```

Выбранные:

```http
POST /admin/users/{user_id}/configs/bulk-delete
Content-Type: application/json
Origin: http://localhost:8080
Idempotency-Key: revoke-selected-1

{"config_ids": ["config-1", "config-2"]}
```

Список — 1..100 уникальных ID. Если хотя бы один ID чужой или неизвестен, вся операция отклоняется до изменений.

Все:

```http
DELETE /admin/users/{user_id}/configs
Origin: http://localhost:8080
Idempotency-Key: revoke-all-1
```

DELETE не принимает тело. Уже deleted считается успешным результатом. Отзыв всех блокирует новые выдачи/активации, пока не обработаны также ранее принятые незавершённые создания. При успешном отзыве серверного peer выставляется DeletedAt; запись, история поколений и зашифрованные файлы сохраняются.

## Принятие и результат

На принятие — 202 Accepted, Location на статус и JSON с operation_id, kind, status, requested_count и деталями элементов. Это не означает, что SSH-операция уже выполнена.

```http
GET /admin/users/{user_id}/config-operations/{operation_id}
```

```json
{
  "operation_id": "operation-id",
  "kind": "create",
  "status": "partial",
  "requested_count": 2,
  "succeeded_count": 1,
  "pending_count": 0,
  "failed_count": 1,
  "items": [
    {"config_id": "config-1", "status": "succeeded", "error_code": null},
    {"config_id": "config-2", "status": "failed", "error_code": "host_operation_unconfirmed"}
  ]
}
```

kind: create / revoke / revoke_all. Статусы родителя: pending, running, succeeded, partial, failed. У элемента: pending, running, succeeded, failed. running входит в pending_count. Ошибка с неподтверждённым результатом не означает, что peer не создан: повтор сначала сверяется с долговечным журналом helper.

Idempotency-Key обязателен: 1..128 печатных ASCII-символов без пробелов. Для повтора используйте тот же ключ и то же тело: вернётся прежняя операция; успешные элементы не выполнятся заново. Другой payload с тем же ключом в той же области даёт 409. Порядок config_ids не влияет на смысл запроса.

Очередь обрабатывается в фоне; ошибки повторяются с задержкой 30 секунд. Повтор исходного запроса с тем же ключом позволяет возобновить failed элементы без этой задержки. После перезапуска незавершённые попытки восстанавливаются из MongoDB; живая lease действует до 2 минут.

Ошибки: 400 неверный запрос, 401 нет сессии, 403 нет прав/неверный Origin, 404 пользователь/конфиг/операция не найдены, 409 конфликт, 503 недоступны зависимости до принятия.

## Настройки и локальный запуск

- INTERNAL_SERVICE_TOKEN — общий случайный токен users и vpn-configs, минимум 32 символа, никогда не передаётся frontend.
- VPN_API_URL для users — адрес vpn-configs (`http://127.0.0.1:8081` локально).
- USERS_API_URL для vpn-configs — адрес users (`http://127.0.0.1:8080` локально).
- VPN_CONFIG_ENCRYPTION_KEY и SSH-настройки — согласно [инструкции helper](../deploy/amnezia/README.md).

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Start-Local.ps1 -WithVPN
```

Скрипт сохраняет существующий .env и добавляет отсутствующий случайный сервисный токен. Users работает с users_local, VPN с vpn_configs_local, оба подключены к отдельной локальной MongoDB на 27018. Внутренний VPN API без сервисного токена отвечает 401; frontend обращается только к users.

Если SSH Provisioner не сконфигурирован (например, VPN_KNOWN_HOSTS_FILE пуст), новый запрос получает 503 без записи операции. Указание проверенного known_hosts включает подключение к хосту: до реальной выдачи нужно установить helper. Настройка адресов не устанавливает helper автоматически.

Реальные выдача/handshake/отзыв на VPN-хосте ещё не проверены. Автоматические тесты используют имитацию хоста и настоящую локальную MongoDB. Новая сводка пользователей с трафиком и обнаружение неназначенных peer остаются отдельной спецификацией admin-user-overview; в этом изменении они не реализованы.
