# PFrame

Single-file PHP 8.4+ micro-framework. Zero dependencies, copy-paste deployment.

One file. 14 classes. ~1650 LOC. Everything you need, nothing you don't.

## Quick Start

```
myproject/
├── public/index.php
├── lib/PFrame.php          # just copy this file
├── config/app.php
├── controllers/
├── templates/
├── logs/
└── tmp/cache/
```

```php
<?php
// public/index.php
declare(strict_types=1);
require dirname(__DIR__) . '/lib/PFrame.php';

class P1 extends \PFrame\Base {}

$app = P1::app();
$app->loadConfig(dirname(__DIR__) . '/config/app.php');

$app->get('/', HomeController::class, 'index');
$app->get('/users/{id}', UserController::class, 'show', name: 'user.show');
$app->post('/login', AuthController::class, 'login');

$auth = \PFrame\Middleware::auth();
$csrf = \PFrame\Middleware::csrf();

$app->group('/admin', function (\PFrame\App $app) use ($csrf): void {
    $app->get('/users', AdminController::class, 'index', name: 'users');
    $app->post('/users', AdminController::class, 'store', mw: [$csrf], name: 'users.store');
}, mw: [$auth], namePrefix: 'admin.');

$app->run();
```

```php
<?php
// config/app.php
declare(strict_types=1);
return [
    'debug' => 0,
    'timezone' => 'Europe/Warsaw',
    'view_path' => dirname(__DIR__) . '/templates',
    'db' => [
        'host' => 'localhost',
        'name' => 'mydb',
        'user' => 'root',
        'pass' => '',
    ],
];
```

## Controllers

```php
<?php
declare(strict_types=1);

class HomeController extends \PFrame\Controller {
    public function index(): \PFrame\Response {
        $users = P1::results('SELECT * FROM users ORDER BY id DESC');
        $pag = $this->paginate(P1::var('SELECT COUNT(*) FROM users'));

        return $this->render('home.php', [
            'users' => $users,
            'pagination' => $pag,
        ]);
    }

    public function create(): \PFrame\Response {
        $this->validateCsrf();
        $data = $this->postData(['name', 'email']);
        $errors = \PFrame\Validator::validate([
            'name' => 'required',
            'email' => ['required', 'email'],
        ], $data);

        if ($errors) {
            return $this->render('form.php', ['errors' => $errors]);
        }

        P1::exec('INSERT INTO users (name, email) VALUES (?, ?)', [$data['name'], $data['email']]);
        return $this->redirectRoute('user.show', ['id' => 1]);
    }
}
```

## Templates

Plain PHP with automatic escaping via `h()`:

```php
<?php $view->layout('layout.php', ['title' => 'Home']); ?>

<h1>Users</h1>
<?php foreach ($users as $user): ?>
    <a href="<?= h($url('user.show', ['id' => $user['id']])) ?>">
        <?= h($user['name']) ?>
    </a>
<?php endforeach; ?>
```

Layout:
```php
<!DOCTYPE html>
<html>
<head><title><?= h($title) ?></title></head>
<body>
    <?php foreach ($flash as $msg): ?>
        <div class="alert-<?= h($msg['type']) ?>"><?= h($msg['text']) ?></div>
    <?php endforeach; ?>
    <?= $content ?>
</body>
</html>
```

## What's Included

| Class | Purpose |
|-------|---------|
| `App` | Router, config, middleware pipeline, error handling |
| `Request` | HTTP request with proxy support |
| `Response` | HTTP response (html, json, redirect) |
| `Db` | PDO wrapper with prepared statements |
| `View` | Template engine with layouts and partials |
| `Controller` | Base controller with auth, CSRF, pagination helpers |
| `Session` | Database-backed session handler with advisory locks |
| `Csrf` | CSRF token + per-action nonce generation |
| `Flash` | Flash messages |
| `Log` | File logger with level filtering |
| `Validator` | Input validation (email, phone, postcode, length, slug) |
| `Cache` | File cache with APCu fallback and rate limiting |
| `Base` | Static facade for app/db/config access |
| `HttpException` | HTTP error responses (401, 403, 404, 405) |

### Global Helpers

- `h($val)` -- HTML escape
- `ha($array, $key)` -- escape array value by key
- `*S()` functions -- null-safe wrappers: `trimS()`, `strlenS()`, `substrS()`, `countS()`, `explodeS()`, `strtotimeS()`, `strip_tagsS()`, `getS()`

## Database

```php
// Via project facade (class P1 extends \PFrame\Base)
$users = P1::results('SELECT * FROM users WHERE active = ?', [1]);
$count = P1::var('SELECT COUNT(*) FROM users');
$user  = P1::row('SELECT * FROM users WHERE id = ?', [$id]);
$names = P1::col('SELECT name FROM users');
$id    = P1::insertGetId('INSERT INTO users (name) VALUES (?)', [$name]);
P1::exec('UPDATE users SET name = ? WHERE id = ?', [$name, $id]);

// Transactions
P1::db()->begin();
// ...
P1::db()->commit(); // or ->rollback()
```

DB sessions require the `sessions` table -- see `db/sessions.sql`.

## Security

Built-in:
- CSRF tokens with `hash_equals()` and HMAC nonces
- Prepared statements everywhere (no string concatenation in SQL)
- XSS protection via `h()` helper (`htmlspecialchars` with `ENT_QUOTES|ENT_HTML5`)
- Security headers middleware (CSP, HSTS, X-Frame-Options, etc.)
- Session hardening (strict mode, httponly, samesite)
- Path traversal protection in template rendering
- Open redirect prevention
- Trusted proxy IP resolution

```php
$app->addSecurityHeaders(); // CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy, HSTS
```

Built-in middleware:
- `\PFrame\Middleware::auth()` -- guest -> flash warning + redirect to `login` route
- `\PFrame\Middleware::csrf()` -- validates token from `csrf_token` field or `X-Csrf-Token` header

## Requirements

- PHP 8.4+
- PDO (MySQL or SQLite)

## Tests

```bash
composer install
vendor/bin/phpunit
```

## License

MIT
