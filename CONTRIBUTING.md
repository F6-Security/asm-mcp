# Участие в разработке

## Окружение

Нужен Python 3.10+.

```sh
python3 -m venv venv
./venv/bin/pip install --require-hashes -r requirements.lock
./venv/bin/pip install --no-deps -e .
./venv/bin/pip install --group dev
```

Зависимости ставятся из лока с проверкой хешей. Сервер держит живой API-токен,
поэтому подменённая зависимость здесь означает утечку доступа, а не просто
сломанную сборку. Для `--group` нужен pip 25.1 или новее.

## Тесты и линт

```sh
./venv/bin/python -m unittest discover -s tests -v
./venv/bin/ruff check .
```

Сеть тестам не нужна. HTTP-клиент подменяется через `httpx.MockTransport`.
`tests/support.py` содержит `FakeASM` — эмулятор `/assets/updated` и
`/issues/updated` с особенностями настоящего API:

- утечка фильтра статуса;
- пустые страницы при маленьком `count`;
- таймауты на больших страницах;
- ответ активов в виде массива.

Handshake по stdio проверяется на установленной команде `asm-mcp`.

## Зависимости

Версии задаются в `pyproject.toml`, а `requirements.lock` генерируется из них.
После правки зависимостей пересоберите лок, иначе CI это заметит:

```sh
uv pip compile pyproject.toml --universal --python-version 3.10 --generate-hashes -o requirements.lock
```

## Проверить сервер вручную

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | ASM_BASE_URL=https://asm.example.com ASM_API_TOKEN=<token> asm-mcp
```

## Структура кода

| Модуль | Содержимое |
| --- | --- |
| `settings.py` | `Settings`: переменные окружения, читаются и проверяются один раз при запуске |
| `catalog.py` | Справочник: типы и статусы, severity, поля, особенности API, список read-only маршрутов `ROUTES` |
| `params.py` | Проверки аргументов: id, курсор, фильтры, маршруты `asm_request` |
| `arguments.py` | Модели аргументов тулов на pydantic. Из одной модели получаются и проверка, и `inputSchema` |
| `client.py` | `ASMClient`: пул соединений, Bearer, троттлинг, ретраи, подсказки по статусам, лимиты ответа |
| `paging.py` | Обход по `seqUpdate`, адаптивный размер страницы, компактный вид записей |
| `summary.py` | Счётчики сводок и фоновые задачи в памяти |
| `server.py` | Тулы (`@tool`), состояние сервера (`AppState`), точка входа `cli` |

Глобального состояния нет. Настройки, клиент, троттлер и фоновые задачи
создаются при старте сервера и живут, пока он работает.

Новый тул добавляется в `server.py`: это функция-обработчик с декоратором
`@tool(имя, модель, описание)`. Модель аргументов описывается классом в
`arguments.py`. Новый read-only эндпоинт подключается записью `Route(...)` в
`catalog.ROUTES`. Эндпоинты, которые меняют данные, туда не добавляются.

## Документация

`README.md` и `README.en.md` должны совпадать по содержанию, раздел в раздел.
Правьте оба файла.

## Релиз

Версия задаётся в `src/asm_mcp/__init__.py` и оттуда попадает в метаданные
пакета, версию MCP-сервера и User-Agent. Публикация на PyPI запускается
публикацией GitHub Release (`.github/workflows/publish.yml`, trusted publishing,
без токенов в секретах). Тег релиза (`vX.Y.Z`) должен совпадать с версией
пакета, иначе публикация остановится.

Ссылки в README абсолютные: PyPI не резолвит относительные пути.
