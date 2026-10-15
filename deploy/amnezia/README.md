# SSH-адаптер для текущего VPN-хоста

Подтверждено владельцем: Ubuntu, контейнер `amnezia-awg2`, `amneziawg-tools v3.1.20260812`, конфиг `/opt/amnezia/awg/awg0.conf`, JSON-таблица `clientsTable` в том же каталоге. Docker публикует `39977/udp` как `39977` для IPv4 и IPv6; текущий внешний VPN endpoint использует порт 39977.

Реализованы Go-адаптер `internal/infrastructure/amnezia` и root-helper `leprechaun_awg.py`. Helper получает один JSON-запрос через stdin, работает с Docker и возвращает JSON через stdout по SSH. Поля запроса не подставляются в shell-команду. Изменения применяются через `awg syncconf`, без перезапуска контейнера.

Это адаптер для указанной установки, а не универсальный API Amnezia. Его ещё не подключили к HTTP/OAuth/фоновому обработчику. На настоящем VPN-хосте он не запускался. Локальные тесты используют имитацию Docker и не подтверждают handshake или прохождение трафика.

## Установка helper — выполняется на VPN-хосте

Python 3 и Docker должны быть доступны. Скопируйте файл `leprechaun_awg.py` из репозитория на хост, затем установите его:

```bash
sudo install -d -m 0755 /usr/local/libexec
sudo install -o root -g root -m 0755 leprechaun_awg.py /usr/local/libexec/leprechaun-awg
```

Для root helper запускается напрямую, для другого SSH-пользователя — через `sudo -n /usr/local/libexec/leprechaun-awg`. Такому пользователю требуется заранее настроенное право запуска этой команды без интерактивного запроса пароля. Helper сам проверяет root.

Не запускайте helper вручную с реальным запросом create/revoke для проверки установки: это изменит VPN. При подготовке достаточно `python3 -m py_compile leprechaun_awg.py`; пробную выдачу нужно делать через согласованный тестовый сценарий после подключения приложения.

## Настройки backend

```dotenv
VPN_HOST_ADDRESS=vpn.example.org:22
VPN_HOST_USERNAME=root
VPN_HOST_PASSWORD=
VPN_KNOWN_HOSTS_FILE=/run/secrets/vpn_known_hosts
VPN_PUBLIC_ENDPOINT=vpn.example.org:39977
```

Последний порт — внешний UDP-порт, а не SSH и не обязательно ListenPort внутри контейнера. Его можно узнать без чтения секретов:

```bash
sudo docker port amnezia-awg2
```

Файл known_hosts нужно заполнить ключом сервера с проверенным отпечатком и передать в окружение backend. Автоматического доверия неизвестному ключу нет. `ssh-keyscan` сам по себе не подтверждает подлинность ключа; отпечаток сверяется через доверенную консоль провайдера.

При Docker-запуске отдельно примонтируйте подготовленный файл только для чтения, например в локальном `compose.override.yaml`:

```yaml
services:
  vpn-configs:
    volumes:
      - ./secrets/vpn_known_hosts:/run/secrets/vpn_known_hosts:ro
```

Содержимое локального каталога secrets не должно попадать в Git. Путь из VPN_KNOWN_HOSTS_FILE относится к контейнеру backend.

## Надёжность и ограничения

- Журнал выдач находится на Ubuntu-хосте в `/var/lib/leprechaun-awg`, каталог 0700, файлы 0600. Он содержит приватный клиентский материал до отзыва; доступ нужен только root. Это отдельное хранилище от зашифрованных файлов в MongoDB.
- Резервируйте журнал вместе с состоянием VPN. Если удалить журнал, теряются сведения об идемпотентности и tombstones отозванных выдач. Helper не принимает отзыв неизвестной выдачи.
- Перед изменением peer сохраняется generation_id, ключи, IP и файл; повтор создания возвращает тот же файл. Отозванная generation_id никогда не восстанавливается. Повторная активация профиля использует новую generation_id.
- Создание резервирует IP в журнале ещё до записи peer, чтобы сбой не привёл к повторной выдаче адреса. Частично применённые операции повторяются с прежними ключами.
- Отзыв удаляет peer из постоянного конфига и применяет его к работающему интерфейсу, проверяет отсутствие ключа в `awg show awg0 peers`, обновляет clientsTable, затем сохраняет tombstone. Только после успеха backend вправе пометить запись deleted.
- Один host-lock сериализует запросы helper от всех backend-экземпляров. Приложение Amnezia этот lock не использует: одновременно управлять клиентами из приложения и backend нельзя. Есть проверка изменений перед записью, но она не устраняет внешнюю гонку между проверкой и записью.
- Существующие чужие peer и записи таблицы сохраняются. Неизвестные форматы конфигов, таблицы или версия инструментов дают ошибку вместо попытки угадать формат.
- Новые файлы выдаются как нативный `.conf`; `vpn://`-упаковка пока не реализована. DNS в новых файлах: 1.1.1.1 и 1.0.0.1, MTU 1280. Применимость нужно проверить реальным тестовым подключением.
- Приватные ключи не передаются через аргументы shell и не печатаются в ошибках; stdout helper содержит секретный клиентский файл и должен читаться только SSH-адаптером.

Основа совместимости: официальные [wireguardConfigurator.cpp](https://github.com/amnezia-vpn/amnezia-client/blob/dev/client/core/configurators/wireguardConfigurator.cpp), [шаблон AWG](https://github.com/amnezia-vpn/amnezia-client/blob/dev/client/server_scripts/awg/template.conf) и [модель clientsTable](https://github.com/amnezia-vpn/amnezia-client/blob/dev/client/ui/models/clientManagementModel.cpp). Ветка dev может меняться; live-проверка нужна на конкретном установленном образе.

## Локальные тесты

```bash
python3 -m unittest discover -s deploy/amnezia -p 'test_*.py' -v
go test ./services/vpn-configs/internal/infrastructure/amnezia
```

Тесты покрывают восстановление после ошибки sync/журнала, неизменяемость повторной выдачи, tombstone, резервирование IP, сохранение чужих клиентов и JSON-протокол SSH.
