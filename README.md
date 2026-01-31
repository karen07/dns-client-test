# DNS client test

DNS client test is a small DNS load generator that resolves domains from a text file at a configurable request rate.

It sends DNS queries to an explicitly selected resolver, tracks the answers, and can export the observed response data. The generated `cache.data` file is understood by the companion `dns-server-test` project, which can replay the captured DNS responses from a local test server.

The optional subnet list filters addresses from `ips.txt` when results are saved. This makes the program useful both for resolver load experiments and for preparing deterministic DNS datasets for other tests.

## Описание

DNS client test - небольшой генератор DNS нагрузки, который разрешает домены из текстового файла с настраиваемой частотой запросов.

Он отправляет DNS запросы на явно выбранный DNS сервер, отслеживает ответы и при необходимости сохраняет полученные данные. Создаваемый файл `cache.data` используется связанным проектом `dns-server-test`, который может воспроизводить сохраненные DNS ответы на локальном тестовом сервере.

Необязательный список подсетей фильтрует адреса при сохранении `ips.txt`. Благодаря этому программу можно использовать как для нагрузочных экспериментов с DNS сервером, так и для подготовки воспроизводимых наборов DNS данных для других тестов.

## Сборка

```sh
cmake --preset release
cmake --build --preset release
```

Исполняемый файл:

```text
build/release/dns-client-test
```

## Использование

```text
Commands:
  Required parameters:
    -f  "/test.txt"   Domains file path
    -d  "x.x.x.x:xx"  DNS server address
    -r  "xxx"         Requests per second
  Optional parameters:
    -b  "/test.txt"   Subnets excluded from ips.txt
    --save             Save DNS response data to cache.data,
                       response domains to out_domains.txt,
                       response IPv4 addresses to ips.txt
```

Пример:

```sh
./build/release/dns-client-test \
    -f domains.txt \
    -d 1.1.1.1:53 \
    -r 1000 \
    --save
```

## Выходные файлы

При `--save` создаются:

- `cache.data` - сериализованные DNS responses для `dns-server-test`;
- `out_domains.txt` - домены, для которых были получены ответы;
- `ips.txt` - найденные IPv4-адреса с учетом фильтра `-b`.

Без `--save` программа работает как генератор/измеритель DNS-запросов и не обязана сохранять результаты на диск.
