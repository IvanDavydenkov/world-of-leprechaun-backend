# VPN Configs Specification

## Purpose
Владение метаданными конфигов и доступ к удалённому хосту Amnezia.

## Requirements

### Requirement: Multiple configs
Модель SHALL поддерживать ноль, один или несколько конфигов пользователя без фиксированного лимита.

#### Scenario: No configs
- **WHEN** запрашиваются конфиги пользователя без назначений
- **THEN** возвращается пустой список

### Requirement: Owner isolation
Система SHALL выбирать конфиг по ID конфига и ID владельца из проверенной identity.

#### Scenario: Foreign config
- **WHEN** пользователь пытается скачать чужой конфиг
- **THEN** содержимое не возвращается
- **AND** обращение к VPN-хосту не выполняется

### Requirement: Host configuration
Сервис vpn-configs SHALL получать адрес, имя пользователя и пароль VPN-хоста из окружения и использовать порт application.Host.

#### Scenario: Configure host
- **WHEN** заданы VPN_HOST_ADDRESS, VPN_HOST_USERNAME, VPN_HOST_PASSWORD
- **THEN** настройки доступны VPN-сервису
- **AND** секреты не выводятся в логи

### Requirement: Metadata persistence
MongoDB SHALL хранить метаданные с owner_id и remote_id; содержимое VPN-конфигов остаётся на удалённом хосте.

#### Scenario: Metadata listing
- **WHEN** читается список конфигов
- **THEN** приватные ключи и удалённые файлы не требуются
