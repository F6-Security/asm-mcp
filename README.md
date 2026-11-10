# F6 ASM MCP Server

[English](https://github.com/F6-Security/asm-mcp/blob/HEAD/README.en.md)

[![PyPI](https://img.shields.io/pypi/v/asm-mcp)](https://pypi.org/project/asm-mcp/)
[![Python](https://img.shields.io/pypi/pyversions/asm-mcp)](https://pypi.org/project/asm-mcp/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/F6-Security/asm-mcp/blob/HEAD/LICENSE)
[![CI](https://github.com/F6-Security/asm-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/F6-Security/asm-mcp/actions/workflows/ci.yml)

MCP-сервер для клиентского API F6 ASM (Attack Surface Management). Через него
ИИ-ассистент получает доступ к внешнему периметру компании: активам (домены, IP,
диапазоны, сертификаты, ПО) и найденным на них проблемам. Можно получать сами
записи с фильтрами или сводные цифры.

## Тулы

| Тул | Назначение |
| --- | --- |
| `asm_list_companies` | Компании, доступные токену. Заодно проверяет адрес, токен и доступ |
| `asm_get_assets` | Активы компании с фильтрами, постранично по `seqUpdate` |
| `asm_get_issues` | Проблемы компании с фильтрами, постранично по `seqUpdate` |
| `asm_get_issue_evidence` | Доказательства по одной проблеме |
| `asm_assets_summary` | Сводка по всем активам: тип, статус, уровень проблем |
| `asm_issues_summary` | Сводка по проблемам: severity, статус, категория, тест, топ хостов и CVE |
| `asm_describe` | Справочник: типы, статусы, severity, поля, лимиты, особенности API. Работает без запроса к API |
| `asm_request` | Остальные эндпоинты, только из фиксированного списка read-only: отчёты, логи, карточка компании, скоринг, утечки |

Все тулы только читают данные. Эндпоинты, которые что-то создают, меняют,
удаляют или переводят статус, `asm_request` отклоняет ещё до отправки запроса.

## Быстрый старт

Понадобятся [uv](https://docs.astral.sh/uv/) (или Python 3.10+ и pip), адрес вашей
инсталляции ASM и API-токен. `uvx asm-mcp` скачивает пакет с PyPI и запускает его
в отдельном окружении, ставить ничего заранее не нужно.

```json
{
  "mcpServers": {
    "asm": {
      "command": "uvx",
      "args": ["asm-mcp"],
      "env": {
        "ASM_BASE_URL": "https://asm.example.com",
        "ASM_API_TOKEN": "<token>"
      }
    }
  }
}
```

Этот блок подходит для Claude Desktop и Cursor. Для VS Code используется файл
`.vscode/mcp.json`: ключ `servers` и `"type": "stdio"`, остальное так же.

Для Claude Code:

```sh
claude mcp add asm \
  -e ASM_BASE_URL=https://asm.example.com -e ASM_API_TOKEN=<token> \
  -- uvx asm-mcp
```

Вместо `uvx` можно поставить пакет командой `pip install asm-mcp` и указать клиенту
команду `asm-mcp`.

Установка из исходников в отдельное окружение:

```sh
cd asm-mcp
python3 -m venv venv
./venv/bin/pip install --require-hashes -r requirements.lock
./venv/bin/pip install --no-deps -e .
```

После этого укажите клиенту `"command": "/path/to/asm-mcp/venv/bin/asm-mcp"` без `args`.
На Windows путь будет `venv\Scripts\asm-mcp.exe`.

Можно запускать в контейнере:

```sh
docker build -t asm-mcp .
docker run -i --rm -e ASM_BASE_URL -e ASM_API_TOKEN asm-mcp
```

Первым вызовом сделайте `asm_list_companies`. Он показывает, что адрес, токен
и доступ к компаниям в порядке.

## Переменные окружения

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `ASM_BASE_URL` | — | Адрес инсталляции ASM, только `https://`. Суффикс `/api/v2` можно указывать или нет |
| `ASM_API_TOKEN` | — | API-токен, передаётся как `Authorization: Bearer` |
| `ASM_CA_BUNDLE` | — | PEM-бандл УЦ для внутреннего сертификата. Заменяет системные УЦ, поэтому в нём должны быть все нужные |
| `ASM_PROXY` | — | Прокси `http://host:port`. Переменные `HTTP_PROXY` и `HTTPS_PROXY` не читаются |
| `ASM_TIMEOUT` | `60` | Таймаут одного запроса, секунд |
| `ASM_RETRIES` | `3` | Число повторов при 429/500/502/503/504 с учётом `Retry-After` |
| `ASM_MIN_INTERVAL` | `1.05` | Пауза между запросами, секунд. Сервер пропускает 1 запрос/с на токен, для платных клиентов 0.1 с |
| `ASM_TOOL_BUDGET` | `40` | Сколько секунд может длиться один вызов тула. Должно быть меньше таймаута MCP-клиента |
| `ASM_SUMMARY_TTL` | `600` | Сколько секунд переиспользуется готовая фоновая сводка |

Выключить проверку TLS нельзя: такой настройки нет намеренно. Для внутреннего
УЦ используйте `ASM_CA_BUNDLE`.

## Примеры

```
asm_list_companies
asm_issues_summary  company_id="…"
asm_get_issues      company_id="…" severity=["crit"] status=["detected"] fields=["alertBody.asset","testName","alertBody.reason"]
asm_get_assets      company_id="…" type=["domain","ip"] status=["confirmed","new"]
asm_get_assets      company_id="…" seq_update="1700000000000_0a1b…"
asm_request         path="reports/<company_id>/last"
asm_request         method="POST" path="dashboard/scores" params={"companyId":"…","dateFrom":"2026-10-01"}
```

Периметр компании — это активы со статусом `confirmed` или `new`. Статус
`false` означает, что актив исключён. Открытые проблемы — это статусы
`detected` и `under review`.

### Пагинация

`asm_get_assets` и `asm_get_issues` идут от старых записей к новым и сами
перелистывают страницы. Один вызов останавливается в одном из трёх случаев:
набрано `max_items` записей, истёк `ASM_TOOL_BUDGET` или ответ дошёл до 1 МБ.
Тогда в ответе будет `complete: false`, причина в `reason` и курсор в
`seqUpdate`. Курсор — это `seqUpdate` последней отданной записи, поэтому при
продолжении записи не пропускаются. Если сохранить `seqUpdate` после полного
обхода, следующий вызов с ним вернёт только изменения.

### Сводки по большим компаниям

Компанию на 10 000+ активов при лимите 1 запрос/с за один вызов не обойти.
Сводка считает, пока хватает `ASM_TOOL_BUDGET`, а затем передаёт посчитанное
и курсор фоновой задаче в процессе сервера. Ответ приходит с `complete: false`
и `job_id`. Повторный вызов с теми же аргументами возвращает прогресс, а после
завершения полный результат. Задачи хранятся только в памяти, файлы не
пишутся. Одновременно идут не больше двух задач.

### Обход особенностей API

- Фильтр `status` в `/issues/updated` пропускает записи с другими статусами.
  Статус и severity перепроверяются на клиенте, а число отброшенных записей
  возвращается в `droppedByFilter`.
- Если задан фильтр и `count` маленький, API отвечает пустой страницей. Поэтому
  при фильтрах `count` не бывает меньше 100, а лишнее обрезается на клиенте.
- Тяжёлые страницы доменов не успевают загрузиться. В этом случае страница
  запрашивается заново в половину размера, но не меньше 50.
- Соответствие severity: `crit/high/medium/low` = `alertSeverity`
  `Crit/Error/Warning/Low` = `alertBody.status` `Critical/High/Medium/Low severity`.
- Тест CVE называется `CVE vulnurability` (именно так, с опечаткой).

## Безопасность

Всё, что возвращают тулы, попадает в контекст языковой модели: периметр
компании, уязвимости, а через `issues/leaks` ещё и утёкшие учётные данные.
Выбирайте провайдера модели с учётом этого. Выдавайте серверу токен с доступом
только к нужным компаниям.

Токен отправляется только на адрес из `ASM_BASE_URL` и только по `https://`.
Редиректы не выполняются. Ответ больше 1 МБ не передаётся модели.

Модель угроз описана в [SECURITY.md](https://github.com/F6-Security/asm-mcp/blob/HEAD/SECURITY.md).

## Участие в разработке

См. [CONTRIBUTING.md](https://github.com/F6-Security/asm-mcp/blob/HEAD/CONTRIBUTING.md).

## Лицензия

[Apache License 2.0](https://github.com/F6-Security/asm-mcp/blob/HEAD/LICENSE)
