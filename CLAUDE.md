# PFrame

@/home/pawel/dev/infra/docs/rules/php-critical.md

Single-file PHP 8.4+ micro-framework. Zero dependencies, copy-paste deployment.

## Architektura

- **Jeden plik:** `src/PFrame.php` — cały framework (~2800 LOC)
- **Namespace:** `PFrame` (klasy) + globalne helpery w `namespace {}`
- **Brak mail:** do maili używamy PHPMailer (zewnętrznie)
- **Fasada:** `PFrame\Base` — projekty definiują `class P1 extends \PFrame\Base`

## Klasy (PFrame namespace)

HttpException, Request, Response, SseResponse, App, Db, View, Session, Csrf, Flash, Middleware, Controller, Log, Validator, Cache, TickTask, Tick, DebugBar, Base (fasada)

## Globalne helpery

`h()`, `ha()`, `getS()`, `strlenS()`, `substrS()`, `trimS()`, `strtotimeS()`, `strip_tagsS()`, `countS()`, `explodeS()`

Konwencja: `nazwaS()` = null-safe wrapper na oryginalną funkcję PHP.

## DB

- `db/sessions.sql` — schemat sesji (MySQL)
- Session handler wspiera SQLite (INSERT OR REPLACE) i MySQL (ON DUPLICATE KEY)
- `Db::trans()` zwraca status aktywnej transakcji
- `Db::count()` zwraca row count ostatniego zapytania (także dla SELECT)
- `Db::log()` zwraca log SQL jako `(X.XXms) SQL`

## Kontrolery i Response

- `Controller` ma data bag `protected array $data` + `set()`/`get()`
- `Controller::render()` łączy data bag z danymi explicit oraz globalami (`flash`, `csrf`, `url`)
- `Response::sendAndExit()` wspiera legacy flow
- `SseResponse` obsługuje Server-Sent Events

## Bezpieczeństwo i obsługa błędów

- Globalny handler: ostrzeżenia → 500, fatale łapane przez shutdown handler
- Router zwraca `405 Method Not Allowed` z nagłówkiem `Allow`
- `App::addSecurityHeaders()` — CSP, HSTS, XFO, XCTO, Referrer-Policy, Permissions-Policy
- `Request::fromGlobalsWithProxies()` + `trusted_proxies` — bezpieczne IP za proxy
- `Session::regenerate()` — po logowaniu
- `Response::redirect()` blokuje external URL gdy HTTP_HOST ustawiony
- `View::renderFile()` chroni przed path traversal

## Worker Mode (FrankenPHP)

`App::resetRequestState()` + `Db::resetRequestState()` — zachowują routes/config/db/PDO, czyszczą timery/log/rowCount.

Worker entrypoint pattern:

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
            if ($db->trans()) { $db->rollbackAll(); }
            $db->resetRequestState();
        }
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
    }
};

if (function_exists('frankenphp_handle_request')) {
    frankenphp_handle_request($handler);
} else {
    $handler();
}
```

Key rules:
- `session_start()` musi być w per-request handlerze, nie podczas bootstrap
- rollback transakcji w `finally` zapobiega tx leak
- `Db::resetRequestState()` wywołuj zawsze (nie warunkuj `log_queries`)
