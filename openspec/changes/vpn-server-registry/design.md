# Административный API VPN-серверов

Маршруты на users (:8080), требуется действующая admin-сессия. POST/PATCH требуют доверенный Origin. Настройки хранятся в коллекции vpn_servers базы VPN-сервиса. Пароль шифруется AES-GCM имеющимся VPN_CONFIG_ENCRYPTION_KEY с отдельным контекстом server_id; ключ остаётся в env. Его нужно резервировать отдельно от MongoDB.

## Создание
POST /admin/vpn-servers, Content-Type: application/json
```json
{
  "name": "Основной VPN",
  "ssh_address": "vpn.example.org:22",
  "ssh_username": "root",
  "password": "your-password",
  "ssh_host_key": "ssh-ed25519 <base64-public-key>",
  "public_endpoint": "vpn.example.org:39977",
  "container": "amnezia-awg2",
  "interface": "awg0"
}
```
Все поля обязательны. ssh_host_key — полный публичный ED25519-ключ, а не SHA256-отпечаток; получить на сервере: cat /etc/ssh/ssh_host_ed25519_key.pub (первые два поля, без комментария). Это публичный ключ, не приватный файл ssh_host_ed25519_key. Запрос не подключается к серверу и не доказывает подлинность присланного ключа; нужна отдельная проверка через доверенную консоль.

Ответ 201, Location: /admin/vpn-servers/{id}. JSON содержит id, name, ssh_address, ssh_username, ssh_host_key, public_endpoint, container, interface, revision=1, password_set=true, created_at, updated_at. Пароля и ciphertext нет.

## Чтение
GET /admin/vpn-servers — массив, отсортированный по id; без записей [].
GET /admin/vpn-servers/{id} — одна запись.

## Изменение
PATCH /admin/vpn-servers/{id}, Content-Type: application/json
```json
{"expected_revision":1,"name":"Резервный VPN","password":"new-password"}
```
Все поля кроме expected_revision необязательны, но хотя бы одно изменение требуется. Пропущенный password сохраняется; null/пустой password отклоняется. Успешный ответ 200 с новой revision. Передавайте revision, полученную последним GET. Конкурирующий или устаревший PATCH даёт 409 без перезаписи. Неизвестные и дублирующиеся поля отклоняются.

401 — нет сессии; 403 — не admin/неверный Origin; 400 — неверные данные; 404 — запись отсутствует; 409 — конфликт revision; 503 — недоступность зависимости. Ответы no-store. Пароль не логируется.

## Граница текущего этапа
Реализован реестр. POST/PATCH не переключают текущий рабочий VPN-хост, не создают/не отзывают peer и не устанавливают helper. Выдача пока использует существующие env. Явный импорт env в реестр, привязка поколений к server_id, check/default и миграция с перевыпуском описаны в openspec/changes/vpn-server-migration и ещё не реализованы. Новую установку регистрируйте отдельным POST, не перезаписывайте ею запись прежнего хоста.