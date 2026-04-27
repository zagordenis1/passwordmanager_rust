# Полная инструкция по использованию `pwm`

> **Языки:** [Українська](USAGE.md) · **Русский**
>
> Документ описывает `pwm` — CLI-утилиту (терминальную команду). Это
> **не** Telegram-бот и не GUI-программа. Всё управление происходит из
> терминала: запустили `pwm` → ввели master-пароль → работаете с
> аккаунтами.
>
> Внутри программы (меню, сообщения об ошибках) — украинский язык, как
> в оригинальном Python-портe. Перевод украинских промптов меню см.
> в [`README.ru.md`](README.ru.md#словарь-перевода-промптов-меню).

Этот файл — детальная пошаговая инструкция. Если нужен лишь краткий
обзор, см. [`README.ru.md`](README.ru.md).

---

## Содержание

1. [Быстрый старт за 60 секунд](#быстрый-старт-за-60-секунд)
2. [Концепции, которые нужно понимать](#концепции-которые-нужно-понимать)
3. [Расположение БД](#расположение-бд)
4. [Интерактивное меню — пункт за пунктом](#интерактивное-меню--пункт-за-пунктом)
5. [Не-интерактивные подкоманды — полный справочник](#не-интерактивные-подкоманды--полный-справочник)
6. [Экспорт / импорт в JSON — детали](#экспорт--импорт-в-json--детали)
7. [Auto-lock — настройка и поведение](#auto-lock--настройка-и-поведение)
8. [Скрипты и автоматизация](#скрипты-и-автоматизация)
9. [Бэкап и перенос на другой компьютер](#бэкап-и-перенос-на-другой-компьютер)
10. [Смена master-пароля](#смена-master-пароля)
11. [Миграция со старой Python-версии](#миграция-со-старой-python-версии)
12. [Частые проблемы (troubleshooting)](#частые-проблемы-troubleshooting)
13. [Коды выхода](#коды-выхода)

---

## Быстрый старт за 60 секунд

```bash
# 1) Сборка (один раз)
cd passwordmanager_rust
cargo build --release

# 2) Установить master-пароль (первый раз)
./target/release/pwm init
#   → введите новый master-пароль дважды

# 3) Добавить аккаунт
./target/release/pwm add --login github --email me@example.com
#   → введите master-пароль, потом сам пароль для github

# 4) Получить пароль
./target/release/pwm get github
#   → введите master-пароль; пароль выводится в stdout

# 5) Или запустите интерактивное меню (без подкоманды)
./target/release/pwm
```

После `cargo install --path .` команды сокращаются до `pwm init`,
`pwm add ...` и т.д.

---

## Концепции, которые нужно понимать

| Понятие              | Что это                                                                                                |
|----------------------|--------------------------------------------------------------------------------------------------------|
| **Master-пароль**    | Один-единственный пароль, который вы запоминаете. Всё остальное шифруется производным от него ключом.    |
| **БД (`users.db`)**  | SQLite-файл с зашифрованными записями. Без master-пароля нечитаем.                                      |
| **Verifier**         | Зашифрованный известный plaintext, позволяющий проверить master-пароль без расшифровки данных.          |
| **KDF**              | Argon2id (по умолчанию) или PBKDF2 (legacy). Преобразует master-пароль в ключ шифрования.                |
| **Fernet**           | Формат симметричного шифрования (AES-128-CBC + HMAC-SHA256), совместим с Python `cryptography.fernet`.  |
| **Auto-lock**        | Автоматический сброс ключа из памяти после N секунд бездействия в интерактивном меню.                   |
| **Запись (record)**  | Один аккаунт: `id`, `login`, `email`, `password`, `created_at`. Шифруется только `password`.             |

---

## Расположение БД

По умолчанию БД создаётся в файле `users.db` в **текущей папке**
(там, откуда запущен `pwm`). Это **не** глобальное хранилище в
`~/.config` или подобном.

Путь к БД задаётся флагом `--db`, его можно указать с любой
подкомандой (включая отсутствующую — тогда запускается меню):

```bash
pwm --db ./personal.db init
pwm --db ./work.db init
pwm --db /home/me/.local/share/pwm/secrets.db get github

pwm --db ~/passwords/main.db    # совместимо с интерактивным меню
```

> **Совет.** Если хотите "глобальное" хранилище — сделайте alias:
> ```bash
> alias pwm='command pwm --db "$HOME/.local/share/pwm/users.db"'
> ```

При первом использовании `--db <путь>`:
- Если файл не существует — он будет создан.
- Если папка не существует — `pwm` вернёт ошибку. Создайте её заранее.

WAL-режим SQLite создаёт два sidecar-файла рядом с `users.db`:
`users.db-wal` и `users.db-shm`. Это нормально.

---

## Интерактивное меню — пункт за пунктом

Запуск без подкоманды:

```bash
pwm                           # users.db в текущей папке
pwm --db ~/secrets/main.db    # свой путь
```

Если master-пароль ещё не задан — пункт меню сразу предложит его
создать. После ввода master-пароля открывается меню (на украинском):

```
=== Password Manager ===
1)  Додати акаунт              → Добавить аккаунт
2)  Знайти акаунт              → Найти аккаунт (по login)
3)  Показати всі акаунти        → Показать все аккаунты
4)  Видалити акаунт             → Удалить аккаунт
5)  Оновити пароль              → Обновить пароль
6)  Експорт у JSON              → Экспорт в JSON
7)  Імпорт з JSON               → Импорт из JSON
8)  Пошук по login/email        → Поиск по login/email (substring)
9)  Вихід                       → Выход
10) Змінити master password     → Сменить master password
11) Згенерувати пароль          → Сгенерировать пароль (без записи в БД)
Виберіть пункт:                 → Выберите пункт:
```

### 1 — Добавить аккаунт

Запрашивает `Login`, `Email`, `Password`. В поле пароля можно ввести
**`g`** вместо настоящего пароля — `pwm` спросит параметры (длина,
классы символов) и сгенерирует. Сгенерированный пароль будет показан и
сохранён.

### 2 — Найти аккаунт

Точное совпадение по `login`. Выводит запись целиком, включая
расшифрованный пароль.

### 3 — Показать все аккаунты

Список всех записей. Если БД пуста — `(порожньо)` (пусто).

### 4 — Удалить аккаунт

Запрашивает login + подтверждение `[y/N]`.

### 5 — Обновить пароль

Запрашивает login + новый пароль (можно `g` для генерации).

### 6 — Экспорт в JSON

Запрашивает путь к файлу (по умолчанию `export.json`). Записывает все
аккаунты JSON-массивом с расшифрованными паролями. **На Unix** файл
создаётся с правами `0600`.

### 7 — Импорт из JSON

Запрашивает путь к файлу. Читает JSON-массив, шифрует каждую запись
**текущим** master-паролем (а не master-паролем БД-источника),
вставляет в БД. Дубликаты по `login` пропускаются.

### 8 — Поиск по login/email

Подстрочный поиск, case-insensitive (для ASCII). `%` и `_` экранируются
автоматически.

### 9 — Выход

Печатает "До побачення." (До свидания.) и выходит с кодом 0.

### 10 — Сменить master password

Спрашивает:
1. Текущий master-пароль (для проверки).
2. Новый master-пароль.
3. Подтверждение нового master-пароля.

Все строки в БД **атомарно перешифровываются** новым ключом в одной
транзакции.

### 11 — Сгенерировать пароль

Просто печатает сгенерированный пароль без записи в БД. **Не
сбрасывает** auto-lock-таймер и **не требует** master-пароля.

---

## Не-интерактивные подкоманды — полный справочник

Все подкоманды поддерживают глобальный флаг `--db <путь>`.
Master-пароль читается:
- из **скрытого prompt'а** — если `stdin` это TTY;
- из **одной строки stdin** — если `stdin` это pipe / файл (для скриптов).

### `pwm init` — первая настройка

```bash
pwm init                                      # запросит master + подтверждение
echo -e "master\nmaster" | pwm init           # неинтерактивно, для CI
```

Падает с ошибкой, если master-пароль уже установлен.

### `pwm add --login <name> [--email <e>] [--stdin]`

```bash
pwm add --login github --email me@example.com
# → master-prompt → password-prompt

# Pipe master + password по одной строке:
printf 'master\nmysecretpw\n' | pwm add --login github --email me@example.com --stdin
```

### `pwm get <login> [--full]`

```bash
pwm get github                # только пароль в stdout
pwm get github --full         # вся запись в stdout
echo "master" | pwm get github | pbcopy           # macOS clipboard
echo "master" | pwm get github | wl-copy          # Wayland clipboard
echo "master" | pwm get github | xclip -selection clipboard   # X11
```

### `pwm list [--json]`

```bash
pwm list                       # человекочитаемый вывод
pwm list --json | jq '.'       # JSON, обработать jq
pwm list --json | jq '.[] | .login'   # только логины
```

### `pwm rm <login> [--force]`

```bash
pwm rm github                   # спросит подтверждение
pwm rm github --force           # без подтверждения
```

### `pwm update <login> [--stdin]`

```bash
pwm update github
printf 'master\nnew-secret\n' | pwm update github --stdin
```

### `pwm change-master`

```bash
pwm change-master
printf 'old\nnew\nnew\n' | pwm change-master    # CI-style
```

### `pwm gen [--length N] [--no-lower] [--no-upper] [--no-digits] [--no-symbols]`

```bash
pwm gen                       # 20 символов, все классы
pwm gen --length 32           # 32 символа
pwm gen --length 24 --no-symbols
```

### `pwm search <query> [--json]`

```bash
pwm search github
pwm search "@example.com" --json | jq
```

### `pwm export <path>`

```bash
pwm export backup.json
pwm export ~/backups/$(date +%Y%m%d)-pwm.json
```

### `pwm import <path> [--no-skip-duplicates]`

```bash
pwm import backup.json                          # дубликаты пропускаются
pwm import backup.json --no-skip-duplicates     # первый дубликат → ошибка
```

---

## Экспорт / импорт в JSON — детали

Я проверил все сценарии вживую на release-сборке; всё работает.

### Формат файла

JSON-массив объектов с полями `id`, `login`, `email`, `password`,
`created_at`:

```json
[
  {
    "id": 1,
    "login": "alice",
    "email": "alice@example.com",
    "password": "pw-alice",
    "created_at": "2026-04-27 20:28:29"
  }
]
```

Поле `password` хранится в **открытом виде** — это и есть смысл
экспорта. Если нужен бэкап БД без расшифровки — просто скопируйте
`users.db` (см. раздел "Бэкап").

### Что делает export

- Расшифровывает все записи текущим master-паролем.
- Сериализует в pretty-printed JSON.
- На Unix создаёт файл с правами `0600` (только владелец). На Windows — стандартный `std::fs::write` (новые файлы наследуют ACL родительской папки).
- Печатает stderr-предупреждение про plaintext-содержимое.

### Что делает import

- Парсит JSON-массив.
- Для каждой записи берёт `login`, `email`, `password` (другие поля игнорируются).
- Пропускает записи с пустым `login` или пустым `password` (или отсутствующим полем `password`) — без ошибки, молча.
- Шифрует **текущим** master-паролем БД-приёмника (не master-паролем БД-источника).
- Вставляет в БД. По `login` срабатывает UNIQUE-ограничение.
- По умолчанию дубликаты по `login` пропускаются. С `--no-skip-duplicates` первый дубликат возвращает ошибку и останавливает импорт.

### Round-trip между двумя БД с разными master-паролями

```bash
pwm --db a.db export shared.json     # расшифровывает master-A
pwm --db b.db import shared.json     # шифрует master-B
rm shared.json                        # ВАЖНО — plaintext!
```

### Edge-cases (проверены вживую)

| Сценарий                                | Результат                                             |
|-----------------------------------------|-------------------------------------------------------|
| Экспорт из пустой БД                    | `[]` в файле, exit 0                                  |
| Импорт `[]`                             | "Імпортовано 0 нових", exit 0                         |
| Импорт несуществующего файла            | `Помилка: reading import file: No such file...`, exit 1 |
| Импорт сломанного JSON                  | `Помилка: parsing JSON array: ...`, exit 1            |
| Импорт объекта вместо массива           | `Помилка: parsing JSON array: invalid type: map...`, exit 1 |
| Запись с пустым login                   | Пропускается молча                                    |
| Запись с пустым password                | Пропускается молча                                    |
| Запись без поля `password`              | Пропускается молча                                    |
| Дубликат login (default)                | Пропускается; счётчик не растёт                       |
| Дубликат login (`--no-skip-duplicates`) | `Помилка: login "X" already exists`, exit 1           |
| Спецсимволы в пароле (Unicode, кавычки, бэкслеши, пробелы) | Сохраняются побайтно             |
| 1000 записей round-trip                 | Все 1000 совпадают побайтно                           |

### Безопасность экспорта

- Экспорт-файл содержит **все ваши пароли в открытом виде**.
- `0600` на Unix защищает от других пользователей машины, но:
  - Если файл попадёт в git/Dropbox/iCloud — пароли скомпрометированы.
  - Если машина бэкапится в незашифрованное хранилище — тоже.
- **Удаляйте экспорт-файл сразу после использования**: `shred -u backup.json` (Linux) или `rm -P backup.json` (macOS).

---

## Auto-lock — настройка и поведение

```bash
PM_AUTO_LOCK_SECONDS=0 pwm        # отключить блокировку
PM_AUTO_LOCK_SECONDS=60 pwm       # 60 секунд
PM_AUTO_LOCK_SECONDS=600 pwm      # 10 минут
unset PM_AUTO_LOCK_SECONDS; pwm   # 300 секунд по умолчанию
```

| Значение     | Поведение                                              |
|--------------|--------------------------------------------------------|
| не задано    | 300 секунд (5 минут)                                   |
| `0`          | Auto-lock полностью отключён                           |
| положительное| Блокировать после N секунд бездействия                 |
| некорректное | Падает к значению по умолчанию (300 с)                 |

**Что сбрасывает таймер.** Любое успешное действие меню (1–8, 10).
Пункты 9 (выход) и 11 (генератор) — **не** сбрасывают.

**Когда таймер проверяется.** После того, как вы ввели номер пункта и
нажали Enter. Если вы оставили `pwm` на промпте меню — ключ остаётся в
RAM до следующего нажатия (известное ограничение, M3 в `docs/audit-2026-04.md`).

**Что происходит при блокировке.** Сессия печатает:
```
Сесію заблоковано через бездіяльність (>300 с). Введіть master password.
```
Даётся 5 попыток ввести master-пароль.

---

## Скрипты и автоматизация

### Pipe master-пароля из файла

```bash
# ❌ ПЛОХО — пароль в shell history
pwm get github <<< "master"

# ✅ ОК — пароль в файле-секрете с 0600
chmod 600 ~/.config/pwm-master
cat ~/.config/pwm-master | pwm get github
```

### Pipe из менеджера паролей ОС

```bash
# Linux: secret-tool
secret-tool lookup pwm master | pwm get github

# macOS: keychain
security find-generic-password -a $USER -s pwm-master -w | pwm get github
```

### Скрипт-обёртка для clipboard

```bash
#!/usr/bin/env bash
# pwm-copy: скопировать пароль в буфер обмена
set -euo pipefail
login="${1:?usage: $0 <login>}"
master_file="${PWM_MASTER_FILE:-$HOME/.config/pwm-master}"

if command -v wl-copy >/dev/null 2>&1; then
  cat "$master_file" | pwm get "$login" | tr -d '\n' | wl-copy
elif command -v pbcopy >/dev/null 2>&1; then
  cat "$master_file" | pwm get "$login" | tr -d '\n' | pbcopy
elif command -v xclip >/dev/null 2>&1; then
  cat "$master_file" | pwm get "$login" | tr -d '\n' | xclip -selection clipboard
else
  echo "no clipboard tool found" >&2
  exit 1
fi
echo "пароль скопирован в буфер обмена"
```

### Bulk-добавление

```bash
#!/usr/bin/env bash
master_file=~/.config/pwm-master
master=$(cat "$master_file")

while IFS=, read -r login email password; do
  printf '%s\n%s\n' "$master" "$password" \
    | pwm add --login "$login" --email "$email" --stdin
done < accounts.csv
```

### Автоматическая ротация master-пароля

```bash
#!/usr/bin/env bash
old_master=$(cat ~/.config/pwm-master)
new_master=$(pwm gen --length 32)

printf '%s\n%s\n%s\n' "$old_master" "$new_master" "$new_master" \
  | pwm change-master

echo -n "$new_master" > ~/.config/pwm-master
chmod 600 ~/.config/pwm-master
```

---

## Бэкап и перенос на другой компьютер

### Способ 1 — копирование `users.db` (рекомендуется)

Зашифрованная БД сама по себе является бэкапом. На приёмнике
master-пароль остаётся тем же.

```bash
# Скопируйте все три файла (sidecar-ы SQLite WAL):
scp users.db users.db-wal users.db-shm new-host:~/passwords/

# Или просто чистый главный файл после `pwm` exit:
pwm --db users.db <<< $'master\n9\n' >/dev/null
scp users.db new-host:~/passwords/
```

Преимущество: master-пароль не нужен; БД переносится в зашифрованном
виде.

### Способ 2 — JSON-экспорт + импорт (для смены master-пароля)

```bash
# На источнике:
pwm --db users.db export portable.json

# Безопасно перенесите файл на целевую машину
# (например через encrypted USB или `gpg --symmetric portable.json`)

# На приёмнике:
pwm --db new.db init           # новый master-пароль может отличаться
pwm --db new.db import portable.json
shred -u portable.json         # ОБЯЗАТЕЛЬНО — plaintext!
```

Преимущество: возможность сменить master-пароль одновременно.
Недостаток: файл содержит plaintext.

---

## Смена master-пароля

### Интерактивно

Меню → пункт 10. Вводите старый, новый, подтверждение.

### Через CLI

```bash
pwm change-master
# → старый → новый → подтверждение нового
```

### Особенности

- Атомарно: всё в одной SQLite-транзакции.
- Перешифровывает **все** записи новым ключом.
- Salt и verifier также обновляются.
- Версия KDF мигрирует на Argon2id (если была legacy PBKDF2).

---

## Миграция со старой Python-версии

Rust-версия читает тот же формат БД, что и Python-версия
[`passwordmanagerpy`](https://github.com/zagordenis/passwordmanagerpy).

```bash
cp ~/old-python/users.db ./users.db
pwm list
# → предупреждение про legacy PBKDF2

pwm change-master
# → старый пароль → тот же новый пароль (дважды)
# → теперь KDF — Argon2id
```

Детали — [`MIGRATION.md`](MIGRATION.md).

---

## Частые проблемы (troubleshooting)

### "DB has no master password yet — run `pwm init` first"

Свежая БД, master-пароль ещё не задан. Выполните `pwm init`.

### "invalid master password"

Неверный master-пароль. В не-интерактивном режиме сразу exit 1.
В меню даётся 5 попыток.

### "master password already set"

`pwm init` на БД, где master-пароль уже установлен. Используйте
`pwm change-master` или удалите `users.db` (зашифрованные данные будут
потеряны).

### "Помилка: parsing JSON array: ..."

Сломанный JSON или не массив верхнего уровня. Проверьте через
`python3 -m json.tool < file.json`.

### "Помилка: reading import file: No such file or directory"

Неверный путь. Проверьте `pwd` и относительные пути.

### "Помилка: login "X" already exists"

Запись с таким `login` уже существует. Используйте `pwm update`,
`pwm rm`, либо при импорте используйте поведение по умолчанию (skip).

### Auto-lock не срабатывает при долгом простое

Если `PM_AUTO_LOCK_SECONDS=0` — он отключён. Если `pwm` стоит на
промпте — таймер проверяется только после Enter (M3).

### `pwm` не найдено в PATH

Запускайте по абсолютному пути или установите глобально:
`cargo install --path .` и добавьте `~/.cargo/bin` в `$PATH`.

---

## Коды выхода

| Код | Когда                                                       |
|-----|-------------------------------------------------------------|
| `0` | Команда выполнилась успешно                                 |
| `1` | Любая ошибка: неверный пароль, не найдено, IO, parse и т.д. |

Stderr содержит описание ошибки на украинском (`Помилка: ...`); stdout — только ожидаемый вывод команды.
