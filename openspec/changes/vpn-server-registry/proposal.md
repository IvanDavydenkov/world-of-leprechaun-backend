# Административный реестр VPN-серверов

## Why
Администратору нужны HTTP-маршруты создания, чтения и изменения настроек VPN-сервера с хранением пароля в зашифрованном виде в MongoDB.

## What Changes
POST /admin/vpn-servers (201), GET /admin/vpn-servers (200 массив), GET /admin/vpn-servers/{id} (200), PATCH /admin/vpn-servers/{id} (200). Поля: name, ssh_address, ssh_username, password только на запись, ssh_host_key (ED25519 public key), public_endpoint, container, interface. Ответ включает id, revision, password_set, created_at, updated_at; пароль/ciphertext не выдаются. PATCH требует expected_revision; пропущенные поля сохраняются; null/пустой пароль/неизвестные поля отклоняются. 409 при конфликте revision.

## Approval
Одобрено пользователем: создать спецификацию и реализовать POST/GET/PATCH. Это этап реестра; переключение реальной выдачи с env на БД, импорт существующего сервера, check/default и миграции поколений остаются отдельным изменением vpn-server-migration. Создание записи не переключает рабочий VPN-хост.

## Security
Текущая admin-сессия на users, Origin на POST/PATCH; внутренний сервисный токен плюс актуальная роль на vpn-configs. 401 без сессии, 403 без admin, 400 неверный JSON/поля/пустой PATCH, 404 отсутствующий ID, 409 revision, 503 зависимость. Cache-Control no-store. AES-GCM с внешним имеющимся ключом, отдельным AAD для server_id и независимым nonce. Валидация адресов/портов и ED25519 key до сохранения. Никаких SSH-вызовов из CRUD. Список по id.