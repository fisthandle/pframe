# PFrame

Single-file PHP 8.4+ micro-framework. Zero dependencies, copy-paste deployment.

One file. 15 classes. ~1800 LOC. Everything you need, nothing you don't.

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
| `Response` | HTTP response (html, json, redirect, send-and-exit helper) |
| `SseResponse` | Streaming HTTP response for Server-Sent Events |
| `Db` | PDO wrapper with prepared statements, tx state and formatted query log |
| `View` | Template engine with layouts and partials |
| `Controller` | Base controller with auth, CSRF, pagination and view data bag helpers |
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

// Compatibility helpers used by migration targets
$inTx = P1::db()->trans();  // bool
$count = P1::db()->count(); // last affected/returned row count
$sqlLog = P1::db()->log();  // "(X.XXms) SQL" lines
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

### Trusted Proxies

`Request::fromGlobalsWithProxies()` trusts forwarded headers only for exact IPs from `trusted_proxies`.

```php
return [
    'trusted_proxies' => ['127.0.0.1', '172.20.0.5'],
];
```

CIDR ranges are not supported. Use exact addresses.

### Worker Mode (FrankenPHP)

Use request-scoped reset when running long-lived workers:

```php
$handler = static function () use ($app): void {
    try {
        $app->resetRequestState();
        session_start();
        $app->run();
    } finally {
        $dbConfig = $app->config('db');
        if (is_array($dbConfig)) {
            $db = $app->db();
            if ($db->trans()) {
                $db->rollback();
            }
            $db->resetRequestState();
        }
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
    }
};
```

### Rate Limiting Helper

`Cache::rateCheck($scope, $id, $max, $window)` is protected by a lock file to keep updates atomic between concurrent requests.

## Migration Compatibility

For F3-to-PFrame migration scenarios, the framework now includes:
- `Db::trans()`, `Db::count()`, `Db::log()`
- `Controller` view data bag (`set()` / `get()`) auto-merged in `render()`
- `SseResponse` for SSE endpoints
- `Response::sendAndExit()` for legacy flow compatibility

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
