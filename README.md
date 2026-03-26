# Backend: Auth + Authorization (Python)

Реализован backend на Python (`Flask`) с собственной системой:
- регистрации / логина / логаута;
- редактирования профиля;
- мягкого удаления аккаунта;
- разграничения доступа по ролям и permissions.

## Запуск

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Сервер стартует на `http://localhost:8000`.

## Основные эндпоинты

- `POST /register` - регистрация (имя, фамилия, отчество, email, пароль, повтор пароля)
- `POST /login` - вход по email/паролю, выдача JWT токена
- `POST /logout` - выход (токен попадает в blacklist)
- `GET /me` - просмотр профиля (требует `profile.read`)
- `PATCH /me` - обновление профиля (требует `profile.update`)
- `DELETE /me` - мягкое удаление аккаунта (требует `account.delete`)
- `GET /resource/<resource_name>` - доступ к ресурсу по требуемому permission
- `GET /admin/roles` - список ролей (только admin)
- `GET /admin/roles/<role_name>/permissions` - получить права роли (только admin)
- `PATCH /admin/roles/<role_name>/permissions` - заменить набор прав роли (только admin)
- `GET /admin/users/<user_id>/roles` - получить роли пользователя (только admin)
- `POST /admin/users/<user_id>/roles` - заменить роли пользователя (только admin)

## Ограничения по полям (валидация)

- `first_name`, `last_name`:
  - обязательные;
  - длина от 2 до 50 символов;
  - допустимы буквы, пробел и дефис.
- `middle_name`:
  - необязательное;
  - если передано, то те же правила, что для имени/фамилии.
- `email`:
  - обязательный в регистрации и логине;
  - проверяется формат;
  - приводится к lowercase;
  - максимум 254 символа;
  - уникальный.
- `password`:
  - длина от 8 до 128 символов;
  - минимум одна буква и одна цифра;
  - `password` и `password_repeat` должны совпадать.
- `PATCH /me`:
  - можно обновить только `first_name`, `last_name`, `middle_name`;
  - пустая строка для `middle_name` означает очистку отчества (`NULL`).

## Схема БД и правила доступа

### Таблицы

- `users`
  - данные пользователя;
  - `is_active` + `deleted_at` для мягкого удаления.
- `roles`
  - роли (`admin`, `user`).
- `permissions`
  - атомарные права (`profile.read`, `profile.update`, ...).
- `role_permissions`
  - связь many-to-many: роль -> permissions.
- `user_roles`
  - связь many-to-many: пользователь -> роли.
- `resources`
  - ресурс + необходимое право (`required_permission`).
- `revoked_tokens`
  - blacklist JWT после logout/удаления пользователя.

### Принцип авторизации

1. Клиент логинится и получает JWT.
2. На каждом защищенном запросе:
   - проверяется наличие/валидность токена;
   - проверяется, что токен не отозван (`revoked_tokens`);
   - определяется пользователь и его permissions через роли.
3. Проверка доступа:
   - нет токена/невалидный токен -> `401 Unauthorized`;
   - токен валиден, но права нет -> `403 Forbidden`;
   - право есть -> доступ к ресурсу выдается.
4. Для админских API (`/admin/...`) дополнительно требуется permission `admin.panel.access`.

## Как выполняются требования 401/403

- `401 Unauthorized`:
  - отсутствует токен;
  - токен невалиден или отозван;
  - пользователь неактивен/удален.
- `403 Forbidden`:
  - пользователь аутентифицирован, но не имеет нужного permission для ресурса.

## Пример минимального сценария

1. Зарегистрироваться через `POST /register`.
2. Войти через `POST /login` и получить `access_token`.
3. Передавать заголовок:
   - `Authorization: Bearer <access_token>`
4. Вызвать `GET /resource/reports` (обычно доступно роли `user`).
5. Вызвать `GET /resource/users-admin`:
   - для `user` -> `403`,
   - для `admin` -> `200`.

## Автотесты

Тесты вынесены в отдельные файлы:
- `tests/test_auth_api.py`
- `tests/test_admin_access.py`
- `tests/test_admin_permissions_api.py`

Запуск всех тестов:

```bash
python3 -m unittest discover -s tests -v
```

## Dev endpoint для быстрого назначения admin

Для локального тестирования вживую доступен endpoint:
- `POST /dev/make-admin`

Тело запроса:
- `email` - email существующего пользователя
- `dev_key` - ключ разработчика (по умолчанию `dev-admin-key`)

Переменные окружения:
- `ENABLE_DEV_ENDPOINTS=1` - включить dev endpoint (по умолчанию включен)
- `DEV_ADMIN_KEY=...` - задать свой dev key

## Тестовый frontend (HTML)

Для ручного тестирования API в браузере добавлен файл:
- `frontend_test.html`

Что умеет страница:
- регистрация и логин;
- просмотр/обновление/удаление профиля;
- проверка доступа к ресурсам;
- вызов админских API (`/admin/...`);
- dev-выдача роли admin через `POST /dev/make-admin`.

Как запустить:

```bash
python3 -m http.server 5500
```

Открыть в браузере:
- `http://127.0.0.1:5500/frontend_test.html`

Важно:
- backend должен быть запущен (`python app.py`);
- в `Base URL` на странице должен быть `http://127.0.0.1:8000` или `http://localhost:8000`.
