# vpnctl

Hysteria2 + VLESS REALITY (gRPC, XHTTP) на своём VPS, с подписками для Hiddify. Один Go-бинарник, без веб-панели.
Каждый VPS независим: своё состояние, свои клиенты, своя подписка.

## Установка и обновление

Первый раз (бинарник собран на ПК: `CGO_ENABLED=0 go build -o vpnctl ./cmd/vpnctl`):

```fish
scp vpnctl <vps>:/tmp/vpnctl
ssh <vps>
/tmp/vpnctl install --name ee
vpnctl add phone
```

Дальше: `vpnctl update --check`, затем `vpnctl update`. Обновление тянет `main` из этого репо,
собирает в контейнере `golang:1.27-alpine` и переприменяет всё через `install`.
Пуш в `main` = то, что поставит следующий `vpnctl update`.

Все команды: `vpnctl help`.

## Каскад (relay)

Для сетей, откуда зарубежный VPS недоступен, а российский доступен. На RU VPS ставится свой vpnctl, затем:

```fish
vpnctl relay add ee <IP ee>
```

RU пробрасывает свои порты на hy2 и gRPC зарубежного VPS как есть (nftables DNAT), ключи остаются только там.
Подписка через RU: `https://<IP RU>:8443/ee/<токен клиента ee>`. RU забирает подписку у ee и добавляет в неё
записи "via ru1" со своими адресом и портами. Зарубежный VPS про RU ничего не знает.

## Что где лежит

На сервере:

| Путь                                       | Что                                       |
|--------------------------------------------|-------------------------------------------|
| `/var/lib/vpnctl/state.json`               | всё состояние: ключи, клиенты, порты, SNI |
| `/var/lib/vpnctl/{hysteria,xray}/`         | конфиги, генерируются из state.json       |
| `/var/lib/vpnctl/compose.yaml`             | контейнеры hysteria и xray                |
| `/var/lib/vpnctl/sub/`                     | сертификат Let's Encrypt для подписок     |
| `vpnctl-sub.service`, `vpnctl-net.service` | сервер подписок и правила nftables        |

В коде:

| Пакет             | Что                                                                   |
|-------------------|-----------------------------------------------------------------------|
| `cmd/vpnctl`      | разбор аргументов, справка                                            |
| `internal/cli`    | команды: install, add/del/list/show, status, logs, sni, update, purge |
| `internal/state`  | state.json, пути, закреплённые версии образов (`versions.go`)         |
| `internal/render` | конфиги hysteria/xray, compose.yaml, ссылки для клиентов              |
| `internal/sys`    | docker, sysctl, nftables, systemd, ufw                                |
| `internal/sub`    | HTTPS-сервер подписок и выпуск сертификата на IP                      |
| `internal/sni`    | поиск и проверка сайта для маскировки REALITY                         |
| `internal/gen`    | пароли, ключи, сертификаты                                            |
| `internal/ui`     | вывод в терминал                                                      |
