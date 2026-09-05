# PFrame

Single-file PHP 8.4+ micro-framework. Zero runtime package dependencies, copy-paste deployment.

Core znajduje się w `src/PFrame.php`; aplikacja może skopiować go do własnego
`lib/` bez dodatkowego pakietu runtime.

## Quick Start

Minimalny przykład działa bez bazy i bez szablonów. Zapisz poniższy plik jako
`myproject/public/index.php`, kopiując wcześniej `src/PFrame.php` do
`myproject/src/PFrame.php`:

```php
<?php
// myproject/public/index.php
declare(strict_types=1);
require dirname(__DIR__) . '/src/PFrame.php';

final class HealthController extends \PFrame\Controller {
    public function index(): \PFrame\Response {
        return $this->jsonSuccess(['service' => 'demo']);
    }
}

$app = new \PFrame\App();
$app->get('/health', HealthController::class, 'index');

$app->run();
```

Uruchom serwer w pierwszym terminalu. `php -S` blokuje ten terminal:

```bash
dev_port=18082 # wybierz wolny port; nie używaj portu z lokalnego rejestru usług
php -S "127.0.0.1:${dev_port:?Podaj port}" -t myproject/public
```

W drugim terminalu ustaw tę samą wartość i wykonaj żądanie:

```bash
dev_port=18082 # ten sam port co w pierwszym terminalu
curl "http://127.0.0.1:${dev_port:?Podaj port}/health"
# {"success":true,"service":"demo"}
```

To jest klasyczny cykl jednego żądania na proces. Dopiero przy użyciu sesji
utwórz `Session`, wywołaj `register()` przed `startSession()` i przed wyjściem
jakiegokolwiek tekstu. Domyślne ciasteczko `secure` zakłada HTTPS; dla lokalnego
HTTP przekaż jawnie `['secure' => false]`.

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
    'max_request_body_bytes' => 8_388_608, // 8 MiB; przekroczenie zwraca 413 przed dispatchem trasy
    'performance' => [
        'server_timing' => false, // true lokalnie: metryki w DevTools/HTTP
        'slow_ms' => 70,          // 0 wyłącza log wolnych requestów
    ],
];
```

The application limit complements, but does not replace, the web-server request-body limit and
PHP's `post_max_size` / `upload_max_filesize`. Configure those limits explicitly, especially for
form and multipart uploads that PHP parses before application code runs.

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
| `Performance` | Bounded request profiler with wall, CPU/wait, memory and named spans |
| `Db` | PDO wrapper with prepared statements, tx state and formatted query log |
| `View` | Template engine with layouts and partials |
| `Controller` | Base controller with auth, CSRF, pagination and view data bag helpers |
| `Middleware` | Built-in middleware factories (`auth`, `csrf`) |
| `Session` | Database-backed session handler with advisory locks, lazy-write and intended URL |
| `Csrf` | CSRF token + per-action nonce generation |
| `Flash` | Flash messages |
| `Log` | File logger with level filtering |
| `Validator` | Input validation (email, phone, postcode, length, slug) |
| `Cache` | Single-backend cache: APCu when available, file otherwise. Rate limiting included |
| `TickTask` | Task definition for periodic background work (interval, time window, callback/command) |
| `Tick` | Scheduler that runs registered `TickTask` instances with global throttle and file-lock dedup |
| `DebugBar` | Request/resource timing + SQL execution/fetch debug overlay renderer |
| `Base` | Static facade for app/db/config access |
| `HttpException` | HTTP error responses (401, 403, 404, 405) |

`Cache` constructor: `new \PFrame\Cache(?string $dir = null)`.  
When APCu is available, `dir` is optional. Without APCu, provide an existing cache directory (constructor fails fast if missing).

## Performance diagnostics

PFrame collects bounded, request-scoped metrics without storing SQL text by default. Built-in spans
cover request parsing, dispatch, route matching, controller execution, response finalization,
database connect/execute/fetch, template rendering, session start and session-lock acquisition.
Database totals include fetching and hydrating results, not only `PDOStatement::execute()`.

```php
$result = $app->measure('forum.prepare_posts', function () use ($posts) {
    return preparePosts($posts);
});

$metrics = $app->performance()->snapshot();
// php_ms, app_ms, cpu_ms, wait_ms, mem_mb, peak_mb, spans
```

Set `performance.server_timing=true` in trusted development environments to expose the metrics in
the standard `Server-Timing` response header. Set `performance.slow_ms` to a positive threshold in
production to write one structured `WARN Slow request` entry with route, status, spans and aggregate
database statistics. Both outputs are disabled by default.

Aggregate query count, total time and fetched rows are always available through
`Db::totalQueryCount()`, `Db::totalQueryTime()` and `Db::totalFetchedRows()`. SQL text, duplicate-query
analysis and slowest-query details remain opt-in through `db.log_queries=true`; this avoids retaining
parameters and growing a per-request SQL log in production.

`cpu_ms` and derived `wait_ms` are reported only on non-thread-safe PHP builds. On ZTS runtimes such
as FrankenPHP they are `null`, because PHP's `getrusage()` reports process-wide CPU and cannot safely
attribute concurrent worker requests. Wall-clock timings and all named spans remain available.

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

DB sessions require the `sessions` table. Use `db/sessions.sql` for MySQL/MariaDB or
`db/sessions.sqlite.sql` for SQLite.

### Session

Database-backed handler with advisory locks (MySQL), lazy-write optimization, and intended URL support.

```php
$session = new \PFrame\Session($db, advisory: true, lockTimeout: 5);
$session->register();
$app->startSession();
```

- **Lazy-write**: when session data is unchanged between `read()` and `write()`, only the timestamp is updated (lightweight `UPDATE` instead of full `INSERT OR REPLACE`)
- **Strict IDs**: unknown client-supplied IDs are rejected through `SessionUpdateTimestampHandlerInterface::validateId()` and PHP generates a fresh ID
- **Locking**: with the MySQL driver, advisory locking uses one `GET_LOCK` call; other drivers use `flock` file locks. The optional `lockDir` constructor argument selects the directory for file locks.
- **Fail-closed lock failure**: if the lock cannot be acquired (timeout or lock error), `read()`, `write()` and `destroy()` return `false`; the caller must handle the failed operation instead of treating it as successful.
- **Intended URL**: `Session::pullIntendedUrl(string $default = '/')` retrieves and clears the URL stored by `Middleware::auth()`

## Security

Built-in:
- CSRF tokens with `hash_equals()` and HMAC nonces
- Prepared statements everywhere (no string concatenation in SQL)
- XSS protection via `h()` helper (`htmlspecialchars` with `ENT_QUOTES|ENT_HTML5`)
- Security headers middleware (CSP, HSTS, X-Frame-Options, etc.)
- Session hardening (strict mode, httponly, samesite)
- Path traversal protection in template rendering
- Open redirect prevention (blocks `//`, `\`, scheme-without-authority, non-http schemes)
- Trusted proxy resolution from exact IPs or resolvable hostnames (nearest untrusted IP from `X-Forwarded-For`)

```php
$app->addSecurityHeaders(); // CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy, HSTS
```

Default CSP:
- `script-src 'self'`
- `style-src 'self' 'unsafe-inline'` (allows built-in error pages and DebugBar styles)

Built-in middleware:
- `\PFrame\Middleware::auth()` -- guest -> stores intended URL in session (GET/HEAD only), flash warning + redirect to `login` route
- `\PFrame\Middleware::csrf()` -- validates token from `csrf_token` field or `X-Csrf-Token` header

After login, retrieve the intended URL with `\PFrame\Session::pullIntendedUrl()` (returns stored path or default `/`, clears session key).

### Error Handling Pipeline

`App` has a built-in 4-stage error pipeline:
1. `3xx` `HttpException` passthrough (redirect-style responses are returned directly)
2. optional custom error handler
3. AJAX fallback (`text/plain`)
4. default inline HTML error page (`text/html; charset=UTF-8`)

Register a custom handler:

```php
$app->setErrorPageHandler(function (
    \PFrame\HttpException $e,
    \PFrame\Request $request,
    \PFrame\App $app
): ?\PFrame\Response {
    // return Response to handle; return null to fallback to framework default
    return null;
});
```

Notes:
- original exception headers (e.g. `Allow` for 405) are preserved in fallbacks
- unhandled `\Throwable` is logged and routed through the same HTTP error pipeline as `HttpException(500)`

### Trusted Proxies

`Request::fromGlobalsWithProxies()` trusts forwarded headers only for exact IPs or resolvable
hostnames from `trusted_proxies`.

```php
return [
    'trusted_proxies' => ['127.0.0.1', '172.20.0.5', 'infra_caddy'],
];
```

CIDR ranges are not supported. Hostnames are resolved to their current IPv4 addresses.

### Worker Mode (FrankenPHP)

Register the session handler once during worker bootstrap, then use `runWorkerRequest()` for each
request. It resets request-scoped state, rolls back leaked DB transactions, resets DB debug
counters/logs, starts the session per request, and closes it in `finally`.

```php
$session = new \PFrame\Session($app->db(), advisory: true, lockTimeout: 5);
$session->register();

$handler = static function () use ($app): void {
    $app->runWorkerRequest(startSession: true);
};

if (function_exists('frankenphp_handle_request')) {
    $maxRequests = max(0, (int) ($_SERVER['MAX_REQUESTS'] ?? 500));
    for ($handled = 0; $maxRequests === 0 || $handled < $maxRequests; $handled++) {
        $keepRunning = frankenphp_handle_request($handler);
        gc_collect_cycles();
        if (!$keepRunning) {
            break;
        }
    }
} else {
    $handler();
}
```

If your worker entrypoint does not use PHP sessions, call `$app->runWorkerRequest()` with
the default `startSession: false`. `MAX_REQUESTS=0` keeps a worker alive without a request limit;
the bounded default periodically recycles the process to contain leaks in application code.

### Rate Limiting Helper

`Cache::rateCheck($scope, $id, $max, $window)` uses stable, bounded striped locks to keep file-backend
updates atomic between concurrent requests. Internal `.pframe-cache-lock-*` files are deliberately
kept by `clear()`; deleting a lock path while another process holds it would break mutual exclusion.

Expired APCu entries are reclaimed by APCu. For the file backend, schedule bounded maintenance so
expired entries that are no longer read do not accumulate:

```php
$removed = $cache->pruneExpired(1000); // maximum removals in one run
```

### Periodic Tasks (Tick)

Register background tasks that run on a timer, optionally within a time window:

```php
$tick = new \PFrame\Tick('/tmp/tick', throttleSeconds: 15, prefix: 'worker-a');
$tick->task('cleanup')
    ->every(3600)
    ->run(fn () => cleanOldRecords());

$tick->task('report')
    ->every(86400)
    ->between('23:00', '02:00')
    ->retries(5)
    ->command('php /app/bin/daily-report.php');

$tick->dispatch(); // call from a cron or worker loop
```

Tasks are deduplicated via file locks and globally throttled (`throttleSeconds`, default `30`).
Time windows support crossing midnight (for example `23:00` → `02:00`).
Failed tasks are retried on subsequent dispatches until `retries()` is exhausted, then they wait a full interval again.

## Testing Traits

`src/PFrameTesting.php` provides PHPUnit traits for integration testing:

The testing helpers intentionally are not part of Composer runtime autoload because they depend on
PHPUnit. Copy `src/PFrameTesting.php` with the core (or use the file from the installed package) and
require it explicitly after PHPUnit's autoloader in `tests/bootstrap.php`:

```php
require dirname(__DIR__) . '/vendor/autoload.php';
require dirname(__DIR__) . '/lib/PFrameTesting.php';
```

| Trait | Purpose |
|-------|---------|
| `DatabaseTransactions` | Wraps each test in a transaction, rolls back all levels (including savepoints) on teardown |
| `RefreshDatabase` | Runs SQL migrations once per suite, wraps tests in transactions |
| `HttpTesting` | `get()`, `post()`, `postJson()`, `put()`, `patch()`, `delete()` with automatic CSRF injection |
| `ResponseAssertions` | `assertOk()`, `assertNotFound()`, `assertRedirectTo()`, `assertSee()`, `assertJsonContains()`, etc. |
| `DatabaseAssertions` | `assertDatabaseHas()`, `assertDatabaseMissing()`, `assertDatabaseCount()` |
| `FlashAssertions` | `assertFlash()`, `assertNoFlash()` |
| `SessionAssertions` | `assertAuthenticated()`, `assertGuest()`, `assertSessionHas()` |
| `ActingAs` | `actingAs($user)`, `actingAsGuest()` for auth simulation |

JSON requests (`postJson`) send CSRF via `X-Csrf-Token` header (matching production JSON API behavior), form requests via `csrf_token` POST field.

## Migration Compatibility

For F3-to-PFrame migration scenarios, the framework now includes:
- `Db::trans()`, `Db::count()`, `Db::log()`
- `Controller` view data bag (`set()` / `get()`) auto-merged in `render()`
- `SseResponse` for SSE endpoints
- `Response::sendAndExit()` for legacy flow compatibility

## Requirements

- PHP 8.4+
- `ext-mbstring`
- `ext-pdo` plus `pdo_mysql` or `pdo_sqlite` for the selected database
- APCu is optional; without it `Cache` uses its file backend

## Tests

```bash
composer install
./bin/test quick
```

Test standard v1 profiles:

```bash
./bin/test quick      # syntax + unit + integration
./bin/test full       # quick + contracts + consumer copies + phpstan
./bin/test ci         # full + coverage report, minimum 85% line coverage
./bin/test coverage   # coverage artifacts, minimum 85% line coverage
./bin/test contracts  # governance/contracts suite
./bin/test e2e        # unsupported in framework repo (exit 2)
./bin/test ui         # unsupported in framework repo (exit 2)
```

Composer aliases:

```bash
composer test
composer test:unit
composer test:integration
composer test:contracts
composer test:quick
composer test:full
composer test:ci
composer test:coverage
composer phpstan
```

Coverage artifacts are generated in `build/coverage/` (`clover.xml`, `html/`). The `coverage` and
`ci` profiles fail if no coverage driver (`xdebug`, `pcov`, `phpdbg`) is available or line coverage
falls below 85%.

## License

MIT
