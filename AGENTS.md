# PFrame

@/home/pawel/dev/infra/docs/rules/php-critical.md

Single-file PHP 8.4+ micro-framework. Zero runtime dependencies, copy-paste deployment.

## Architektura

- **Jeden plik:** `src/PFrame.php` — cały framework (~4300 LOC)
- **Namespace:** `PFrame` (klasy) + globalne helpery w `namespace {}`
- **Brak mail:** do maili używamy PHPMailer (zewnętrznie)
- **Fasada:** `PFrame\Base` — projekty definiują `class P1 extends \PFrame\Base`

## Klasy (PFrame namespace)

HttpException, Request, Response, SseResponse, Performance, App, Db, View, Session, Csrf, Flash, Middleware, Controller, Log, Validator, Cache, TickTask, Tick, DebugBar, Base (fasada)

## Globalne helpery

`h()`, `ha()`, `getS()`, `strlenS()`, `substrS()`, `trimS()`, `strtotimeS()`, `strip_tagsS()`, `countS()`, `explodeS()`

Konwencja: `nazwaS()` = null-safe wrapper na oryginalną funkcję PHP.

## DB

- `db/sessions.sql` — schemat sesji (MySQL/MariaDB)
- `db/sessions.sqlite.sql` — schemat sesji (SQLite)
- Session handler wspiera SQLite (INSERT OR REPLACE) i MySQL (ON DUPLICATE KEY)
- `Db::trans()` zwraca status aktywnej transakcji
- `Db::count()` zwraca row count ostatniego zapytania (także dla SELECT)
- `Db::log()` zwraca log SQL jako `(X.XXms) SQL`
- `Db::totalQueryCount()` / `totalQueryTime()` / `totalFetchedRows()` zbierają lekkie agregaty także przy `log_queries=false`
- czas zapytania obejmuje przygotowanie, wykonanie i pobranie wyników; szczegółowy log rozdziela `execute_time` i `fetch_time`

## Wydajność

- `App::performance()` udostępnia profiler requestu, a `App::measure($name, $callback)` dodaje własny span
- automatyczne spany obejmują request/router/controller/finalize, DB connect/execute/fetch, widoki oraz start i blokadę sesji
- `performance.server_timing=true` dodaje standardowy nagłówek `Server-Timing`; domyślnie jest wyłączony
- `performance.slow_ms=N` loguje requesty od progu `N` ms razem ze spanami i agregatami DB; `0` wyłącza log
- na PHP ZTS `cpu_ms` i `wait_ms` są `null`, bo `getrusage()` mierzy cały współbieżny proces; wall time i spany pozostają poprawne
- używaj `$app->startSession()` zamiast surowego `session_start()`, aby zmierzyć oczekiwanie na start sesji

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
- `max_request_body_bytes` domyślnie wynosi `8_388_608` (8 MiB); przekroczenie kończy się `413` przed middleware i dispatchem trasy
- limit aplikacyjny nie zastępuje limitów serwera WWW ani `post_max_size` / `upload_max_filesize`, szczególnie dla form i uploadów parsowanych przed kodem aplikacji
- `Session::regenerate()` — po logowaniu
- handler sesji implementuje `validateId()`; bez tego `session.use_strict_mode=1` nie odrzuca obcego ID
- `Response::redirect()` blokuje external URL gdy HTTP_HOST ustawiony
- `View::renderFile()` chroni przed path traversal

## Worker Mode (FrankenPHP)

W klasycznym FPM najpierw wywołaj `$session->register()`, potem `$app->startSession()`, a na końcu
`$app->run()`. Domyślne `secure=true` wymaga HTTPS; wyłączenie jest dopuszczalne tylko jawnie
dla lokalnego HTTP.

W workerze zarejestruj handler sesji raz podczas bootstrapu. `runWorkerRequest()` zachowuje
routes/config/db/PDO, a per request czyści stan, zabezpiecza transakcje oraz otwiera i zamyka sesję.

Worker entrypoint pattern:

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

Key rules:
- `Session::register()` podczas bootstrapu, `session_start()` per request przez `runWorkerRequest()`
- preflight i `finally` robią `rollbackAll()` oraz reset DB, więc tx/log/rowCount nie przeciekają
- bez sesji użyj domyślnego `startSession: false`
- `MAX_REQUESTS=0` oznacza brak limitu; domyślne 500 okresowo recyklinguje proces, a po każdym żądaniu uruchamiany jest GC

## Testy

bin/test profiles: `quick|full|ci|coverage|contracts|e2e|ui`
- `bin/test quick` — składnia + Unit + Integration
- `bin/test full` — quick + Contracts + Consumer copies + PHPStan
- `bin/test ci` — full + coverage z minimalnym pokryciem linii 85%; brak drivera kończy profil błędem
- `composer test` = alias do `bin/test quick`

`src/PFrameTesting.php` zależy od PHPUnit i nie jest częścią runtime autoload. Konsument kopiuje
ten plik osobno i wymaga go jawnie w `tests/bootstrap.php` po `vendor/autoload.php`.

PHPUnit 13 nie obsługuje `-v`; gdy potrzebny jest szczegółowy przebieg, użyj `--debug`.

## Build

- `composer install` — odtwarza zależności i autoloader do lokalnej walidacji biblioteki.

## Lint / static analysis

- `composer phpstan` — uruchamia PHPStan dla kodu frameworka w `src/`.

## Konsumenci

Kopie `PFrame.php` i `PFrameTesting.php` w projektach pod `/home/pawel/dev` sprawdza:

```bash
./bin/check-consumers.sh /home/pawel/dev
```

Skrypt jest tylko do odczytu: porównuje kopie z `src/`, raportuje rozjazdy i nie synchronizuje plików.

## Gotchas

- `paginate()` zwraca `per_page`/`offset`, NIE `limit`
- `Response::statusCode()` — usunięty
- `$app->addMiddleware(...)` — NIE `$app->use(...)`
- `App::instance()` throws `LogicException` przy konflikcie klas
- `example/` jest w `.gitignore` — footgun przy demo
- Flash PRZED session clear — `session_regenerate_id(true)` nie `destroy()`
- Logout = POST + CSRF (nie GET)
- `$app->get()` nie `addRoute()` — sprawdzaj istniejące wzorce routingu
- Nested transactions w testach: `rollbackAll()` nie pojedynczy `rollback()`
- `TickTask::command()` uruchamia przez shell — `;` i `&&` wykonywane, wymaga allowlisty/escaping
- CSP: `style-src 'unsafe-inline'` wymagane (error pages, DebugBar); scripts bez `unsafe-inline`
- `trusted_proxies` = exact IPs lub resolvable hostnames (np. `infra_caddy`), nie CIDR
- Cache: jeden backend per request (APCu-only gdy dostępny, file-only bez APCu); file backend ma trwałe, ograniczone stripe locki, których `clear()` nie usuwa
- `Cache::pruneExpired(1000)` uruchamiaj okresowo przez `Tick`/cron, bo nieodczytywane wygasłe pliki nie sprzątają się same
- OPcache preload: `require_once`, nie `opcache_compile_file`
- `Tick`: `tryLock()` = flock only; `between()` wspiera okna przez północ; `inTimeWindow(?string $now)` testowalny

## Konwencje i zakres

- Zachowuj 1TBS/K&R (otwierający nawias w tej samej linii) oraz polskie komunikaty użytkowe.
- Null-safe wrappery na funkcje PHP mają sufiks `S` (`trimS`, `countS`, `strtotimeS`). Nie twórz równoległej konwencji.
- `src/PFrame.php` jest źródłem prawdy. Przy zmianie SQL zaktualizuj testy, które celowo asertują literalne zapytania; po nieudanym patchu najpierw przeczytaj świeży diff i bieżący fragment pliku.
- Producentami kopii konsumenckich są `src/PFrame.php` i `src/PFrameTesting.php`; checker obejmuje `*/lib/` oraz `*/app/lib/`, bez ręcznych list, hashy ani statusów synchronizacji.
- `example/` jest ignorowane przez Git. Jeśli świadomie zmieniasz demo, waliduj je osobno i nie zakładaj, że pojawi się w `git status`.

## Wiedza i stan pracy

- Ten rootowy `AGENTS.md` jest kanoniczną instrukcją. `.codex/napkin.md` jest krótkim inboxem niepromowanych korekt; usuń wpis po utrwaleniu go w kodzie, teście lub tutaj.
- Dłuższe, zweryfikowane rozwiązanie umieść w dokumentacji tematycznej. Jeśli powstanie backlog, użyj jednego `tasks/TODO.md`.
- Nowy plan w `docs/plans/` musi mieć status `draft`, `approved`, `active`, `done` albo `superseded`. Nie zakładaj, że istniejący plan jest aktywny bez porównania z kodem.
