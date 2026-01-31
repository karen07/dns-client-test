# DNS client test

DNS client test is a small UDP DNS load generator for reproducible DNS experiments.

It reads domains from a text file, sends either `A` or `HTTPS` queries to a selected resolver at a configurable rate, and can save raw DNS responses for replay with `dns-server-test`. An optional random sample mode makes it possible to run the same experiment on a smaller subset of a large domain list.

The program can also write a human-readable DNS log showing the Question type and the records returned in the Answer, Authority, and Additional sections.

## Описание

DNS client test - небольшой генератор UDP DNS нагрузки для воспроизводимых DNS-экспериментов.

Программа читает домены из текстового файла и отправляет запросы на явно указанный DNS resolver с заданной частотой. Поддерживаются два режима, которые нужны для текущих тестов:

- `A` (`QTYPE=1`) - обычное разрешение IPv4;
- `HTTPS` (`QTYPE=65`) - HTTPS Resource Record.

По умолчанию используется `A`. Для явного выбора можно использовать `-A`/`--a` или `-H`/`--https`.

CNAME отдельно запрашивать не требуется. Если имя является CNAME, resolver возвращает CNAME внутри ответа на запрошенный тип. Например, запрос `A` может вернуть `CNAME -> A`, а запрос `HTTPS` - `CNAME -> HTTPS`.

При необходимости клиент сохраняет сырые DNS-ответы в cache-файл для `dns-server-test`, отдельный список ответивших доменов, IPv4 из настоящих `A` records и человекочитаемый лог.

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
Required:
  -f path            Файл со списком доменов
  -d IPv4:port       Адрес DNS resolver
  -r RPS             Количество DNS-запросов в секунду

Optional:
  -A, --a            Запрашивать A (по умолчанию)
  -H, --https        Запрашивать HTTPS (QTYPE=65)
  -n count           Случайно выбрать count доменов из входного файла
  --seed seed        Seed случайной выборки
  -b path            IPv4-подсети, исключаемые из ips-*.txt
  --save             Сохранять DNS-ответы и результаты
  --log              Записывать человекочитаемый DNS-лог
```

Без `-n` обрабатывается весь входной файл.

### A-прогон по всему файлу

```sh
./build/release/dns-client-test \
    -f domains.txt \
    -d 1.1.1.1:53 \
    -r 300 \
    -A \
    --save \
    --log
```

Так как `A` является режимом по умолчанию, `-A` можно не указывать.

### HTTPS-прогон по всему файлу

```sh
./build/release/dns-client-test \
    -f domains.txt \
    -d 1.1.1.1:53 \
    -r 300 \
    -H \
    --save \
    --log
```

### Случайные 100 000 доменов

```sh
./build/release/dns-client-test \
    -f top-1000000.txt \
    -d 1.1.1.1:53 \
    -r 300 \
    -H \
    -n 100000 \
    --save \
    --log
```

Клиент выбирает ровно `N` различных позиций из входного файла без предварительного копирования всего списка в память. Если `N` больше или равно числу доменов во входном файле, обрабатывается весь файл.

Если `--seed` не задан, для случайной выборки используется автоматически созданный seed, который выводится при запуске. Его можно затем указать явно для повторения той же выборки.

Например, чтобы сравнить `A` и `HTTPS` на одних и тех же 100 000 доменах:

```sh
./build/release/dns-client-test \
    -f top-1000000.txt \
    -d 1.1.1.1:53 \
    -r 300 \
    -A \
    -n 100000 \
    --seed 12345 \
    --save \
    --log

./build/release/dns-client-test \
    -f top-1000000.txt \
    -d 1.1.1.1:53 \
    -r 300 \
    -H \
    -n 100000 \
    --seed 12345 \
    --save \
    --log
```

Одинаковые входной файл, `-n` и `--seed` дают одинаковую выборку доменов.

## Вывод в консоль

Во время работы клиент раз в секунду печатает статистику:

```text
Send_RPS; Read_RPS;   Sended;   Readed;     Diff;
      300;      297;   998404;   994839;     3565;
```

Поля означают:

- `Send_RPS` - фактическая скорость отправки DNS-запросов;
- `Read_RPS` - фактическая скорость получения DNS-ответов;
- `Sended` - всего отправлено запросов;
- `Readed` - всего получено UDP-ответов;
- `Diff` - разница между отправленными запросами и полученными ответами.

## Выходные файлы

Имя каждого выходного файла содержит режим прогона, поэтому `A` и `HTTPS` можно запускать в одном каталоге без перезаписи результатов друг друга.

При `A` создаются:

```text
cache-A.data
out_domains-A.txt
ips-A.txt
log-A.txt            # только при --log
```

При `HTTPS` создаются:

```text
cache-HTTPS.data
out_domains-HTTPS.txt
ips-HTTPS.txt
log-HTTPS.txt        # только при --log
```

`cache-*.data` содержит полные корректно разобранные DNS responses в существующем бинарном формате `dns-server-test`. Сохраняются и ответы с `ANCOUNT=0`, например NODATA или NXDOMAIN.

`out_domains-*.txt` содержит домены, для которых были получены и успешно разобраны ответы.

`ips-*.txt` содержит только IPv4 из настоящих `A` records секции Answer. `ipv4hint` внутри `HTTPS` record туда намеренно не записывается. Поэтому `ips-HTTPS.txt` может быть пустым даже при наличии `ipv4hint` в HTTPS-ответах.

Необязательный `-b` фильтрует адреса только при записи `ips-*.txt`.

## Человекочитаемый лог

Параметр `--log` включает подробный DNS-лог.

Пример `log-HTTPS.txt`:

```text
20:40:00 Q(65) 001win2.cc rcode=0 an=2 ns=0 ar=0
    AN CNAME 001win2.cc zhu-2052852.t-h-1-x.com ttl=600
    AN HTTPS zhu-2052852.t-h-1-x.com priority=1 target=. ttl=300 ipv4hint=8.6.112.0,8.47.69.0
```

Первая строка содержит:

- `Q(x)` - QTYPE исходного DNS-запроса;
- `rcode` - DNS response code;
- `an` - число Resource Records в Answer;
- `ns` - число Resource Records в Authority;
- `ar` - число Resource Records в Additional;
- `TC` - пометка truncated UDP response.

Обозначения секций:

- `AN` - Answer;
- `NS` - Authority;
- `AR` - Additional.

Для `A` логируется IPv4 и TTL:

```text
AN A example.com 203.0.113.10 ttl=300
```

Для `CNAME` логируются owner и target:

```text
AN CNAME example.com edge.example.net ttl=300
```

Для `HTTPS`/`SVCB` выводятся поля, полезные для анализа:

```text
priority=<value>
target=<name>
ipv4hint=<IPv4,...>
```

`priority=0` соответствует AliasMode, `priority>0` - ServiceMode.

Остальные известные RR-типы выводятся по имени, неизвестные - как `RR(number)` с длиной RDATA. Клиент не пытается превращаться в полноценный DNS resolver: лог нужен прежде всего для того, чтобы видеть фактическое содержимое ответов.

## Совместимость с dns-server-test

Бинарный формат cache-файла не изменен.

Так как клиент теперь создает `cache-A.data` и `cache-HTTPS.data`, в `dns-server-test` удобно использовать параметр `-c` для выбора cache-файла:

```sh
./dns-server-test -l 127.0.0.1:5353 -c cache-A.data
```

или:

```sh
./dns-server-test -l 127.0.0.1:5353 -c cache-HTTPS.data
```

A и HTTPS cache-файлы намеренно остаются раздельными. Благодаря этому серверу не требуется усложнять индекс до `(domain, QTYPE)`: один запуск сервера воспроизводит один тип собранных ответов.
