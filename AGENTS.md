# PFrame

@/home/pawel/dev/infra/docs/rules/php-critical.md

Single-file PHP 8.4+ micro-framework. Zero runtime dependencies, copy-paste deployment.

## Architektura

- **Jeden plik:** `src/PFrame.php` — cały framework
- **Namespace:** `PFrame` (klasy) + globalne helpery w `namespace {}`
- **Brak mail:** do maili używamy PHPMailer (zewnętrznie)
- **Fasada:** `PFrame\Base` — projekty definiują `class P1 extends \PFrame\Base`

## Klasy (PFrame namespace)

HttpException, SessionLockException, Request, Response, SseResponse, Performance, App, Db, View, Session, Csrf, Flash, Middleware, Controller, Log, Events, Validator, Cache, TickTask, Tick, DebugBar, Base (fasada)

## Globalne helpery

`h()`, `ha()`, `getS()`, `strlenS()`, `substrS()`, `trimS()`, `strtotimeS()`, `strip_tagsS()`, `countS()`, `explodeS()`

Konwencja: `nazwaS()` = null-safe wrapper na oryginalną funkcję PHP.

## DB

- `db/sessions.sql` — schemat sesji (MySQL/MariaDB)
- `db/sessions.sqlite.sql` — schemat sesji (SQLite)
- Session handler wspiera SQLite (INSERT OR REPLACE) i MySQL (ON DUPLICATE KEY)
- Niezmieniona sesja odświeża `stamp` najwyżej raz na 60 s (przy krótkim `session.gc_maxlifetime` co 1/10 czasu życia), więc zwykłe żądanie nie zapisuje nic do tabeli `sessions`, a `stamp` może być starszy od ostatniej aktywności o ten odstęp
- `Db::trans()` zwraca status aktywnej transakcji
- SQLite: `begin('immediate')` bierze blokadę zapisu na początku transakcji; `transaction($callback, 'immediate')` robi commit lub rollback i przekazuje `Db` do callbacka. Tryb immediate jest odrzucany przy zagnieżdżeniu i poza SQLite; `begin()` bez argumentów zachowuje dotychczasowy tryb.
- Oczekiwanie na `BEGIN IMMEDIATE` jest mierzone osobnym spanem `db.begin`, bez zwiększania `db_count`
- `sqlite_pragmas` w konfiguracji Db ustawia i weryfikuje przy połączeniu: `foreign_keys`, `journal_mode`, `synchronous`, `busy_timeout`, `trusted_schema`
- `Db::count()` zwraca row count ostatniego zapytania (także dla SELECT)
- `Db::execScript()` wykonuje zaufany, wieloinstrukcyjny skrypt migracyjny SQLite i zapisuje go jako jedno zdarzenie `sql`
- `Db::log()` zwraca log SQL jako `(X.XXms) SQL`
- `Db::totalQueryCount()` / `totalQueryTime()` / `totalFetchedRows()` zbierają lekkie agregaty także przy `log_queries=false`
- czas zapytania obejmuje przygotowanie, wykonanie i pobranie wyników; szczegółowy log rozdziela `execute_time` i `fetch_time`

## Wydajność

- `App::performance()` udostępnia profiler requestu, a `App::measure($name, $callback, $details = [])` dodaje własny span; `$details` to wyłącznie `array<string, scalar|null>`
- automatyczne spany obejmują request/router/controller/finalize, DB connect/execute/fetch, widoki oraz start i blokadę sesji
- `performance.server_timing=true` dodaje standardowy nagłówek `Server-Timing`; domyślnie jest wyłączony
- `performance.slow_ms=N` loguje requesty od progu `N` ms razem ze spanami i agregatami DB (wzorzec trasy zamiast ścieżki, bo parametry bywają sekretami); `0` wyłącza log
- `performance.trace=true` zapisuje JSONL w `YYYYMMDD_perf.jsonl` (jedna linia na request, wszystkie zdarzenia, bez samplingu) z chronologicznymi spanami, każdym szablonem i SQL przez `Db` (bez rozwijania parametrów); `run()`/worker domykają ślad po wysyłce i zapisie sesji. To standardowe źródło danych wydajności dla aplikacji
- format v2 (tylko dodaje pola): top-level `v=2`, `request_id`, `pid`, `sapi`, `connection_aborted` (bool), `fatal` (`null` albo typ błędu fatalnego; `error` bez zmian); `performance.children_cpu_ms` (RUSAGE_CHILDREN); każde zdarzenie ma `id` i `parent` (id otaczającego spanu albo `null`), a spany dodatkowo `cpu_ms` i `mem_kb` (`memory_get_usage(false)`); najwyżej 5000 zdarzeń na request, nadmiar liczy `dropped_events` (chroni długie procesy CLI/cron, które zbierają zdarzenia bez zapisu)
- `requestId()` (`App`/`Performance`) przejmuje przychodzący `X-Request-ID` pasujący do `^[A-Za-z0-9._-]{8,64}$`, inaczej generuje 16 znaków hex; świeży po `resetRequestState()`/w każdym żądaniu workera. Odpowiedzi z `handle()` i strona fatala dostają nagłówek `X-Request-ID`, jeśli go nie ustawiono
- `measureHttp($service, $curlHandle)` zastępuje `curl_exec()` spanem `http.request` (`service`, `http_status`, `total_ms`, `dns_ms`, `connect_ms`, `tls_ms`, `ttfb_ms`, `bytes`, `curl_errno`); bez trace to czyste `curl_exec()`
- `measureProcess($program, $callback)` mierzy proces w spanie `process.exec` (`program`, `children_cpu_ms`, `exit_code` z wyniku `int` albo tablicy z intowym `exit_code`, inaczej `null`) i zwraca wynik callbacka bez zmian; callback musi poczekać na proces (`proc_close()`), aby jego CPU trafiło do RUSAGE_CHILDREN
- na PHP ZTS `cpu_ms`, `wait_ms` i `children_cpu_ms` są `null`, bo `getrusage()` mierzy cały współbieżny proces; wall time i spany pozostają poprawne
- używaj `$app->startSession()` zamiast surowego `session_start()`, aby zmierzyć oczekiwanie na start sesji

## Dziennik zdarzeń (Events)

- Opcjonalny dziennik do odtwarzania sesji: `events.enabled=true` zapisuje `YYYYMMDD_events.jsonl` w `events.dir`. Ustawiaj `events.dir` jawnie; bez niego i bez `Log::init` zdarzenia nie są zapisywane (jedno ostrzeżenie w `error_log`). Proces bez `App` (CLI, worker) włącza warstwę przez `Events::configure([...])`.
- Klucze: `enabled`, `dir`, `retention_days` (90), `aggregate_routes` (wzorce tras → zbiorcza linia `http/poll` na minutę przez APCu), `ignore_tables` (`['sessions']`), `mask_params` (dodatkowe nazwy parametrów/query z wolnym tekstem).
- Koperta v1: `v`, `ts`, `source` (`web`, `cli:<skrypt>`, `cron:<zadanie>`, `worker:<rola>` albo własne), `request_id` (web) lub `run_id`, `actor` (`user:<id>`, `api:<źródło>`), `actor_start`, `sid` (skrót sesji), `sid_new`, `category`, `action`, `subject` (`<typ>:<id>`), `outcome` (`ok|rejected|failed|shown`), `duration_ms`, `ctx`.
- Automatycznie: `http/request` raz na żądanie po wysyłce, w shutdownie (po zamknięciu sesji) albo na końcu żądania workera, także przy 413, blokadzie sesji, `exit()` i fatalu; zapisy SQL w `ctx.writes` (`insert|update|delete tabela`, wiersze, do 5 ID), bez wycofanych rollbackiem — także surowym `SAVEPOINT`/`ROLLBACK TO` przez `Db::exec` — osobno dla każdego połączenia `Db`; puste UPDATE/DELETE są pomijane, a bezpośrednie `$db->pdo()->exec()` niewidoczne; `ui/flash_added` i `ui/flash_rendered` z `PFrame\Flash` z typem, `text_id` (skrót treści) i długością, bez treści (`shown` = wyrenderowane, nie dowód wyświetlenia); `run/end` dla zadań `Tick`, a komendy Ticka dostają `PFRAME_RUN_ID`; odrzucenie `Middleware::csrf()` daje `auth/csrf_failed`. `Location` trafia jako wzorzec trasy (obce adresy jako sam host). Odpowiedź wysłana przed `run()` wymaga `$app->trackRequestEvent()` na początku front controllera.
- Konsument: `Events::startCli($argv[0])` w bootstrapie CLI (dziedziczy `run_id` z env `PFRAME_RUN_ID`, który rodzic ustawia dla procesów potomnych); `Events::startRun($source, $runId)` + `finishRun($ctx, $outcome, $onlyIfUsed)` + `resume($previous)` wokół iteracji własnych workerów; `Events::setActorResolver()` gdy aktor nie jest w `$_SESSION['user']['id']`; `Events::record($category, $action, $ctx, $subject, $outcome)`; `Events::maintain()` raz na noc (kompresja zamkniętych dni po weryfikacji archiwum, retencja, usuwanie aktorów z `Events::queueForget('user:ID')`; nie rzuca wyjątków, błąd zwraca jako `failed=<klasa>`); zdarzenia klienta (beacony) wskazują stronę w `ctx.page_request_id`, a odtworzenie łączy je z żądaniem strony; testy resetują stan przez `Events::disable()`.
- Słownik: `auth/login|login_failed|logout|csrf_failed|impersonate`; `entity/created|updated|deleted` z `subject=<typ>:<id>` i nazwami pól w `ctx.field(s)`, bez wartości; kanał wyjściowy jako kategoria (`email`, `sms`, `telegram`, `voice`, `http`) z czasownikiem (`queued|sent|failed|retry|attempt`) i identyfikatorami w kluczach `*_id`; `log/warn|error` z miejscem wywołania, nie treścią. Nie zapisuj treści wiadomości, numerów telefonów, adresów, tokenów ani wartości pól.
- Lista dozwolonych danych: w `ctx` zostają liczby, wartości logiczne, identyfikatory (`id`/`*_id`), daty i ciągi bez spacji do 64 znaków; tekst ze spacjami staje się `[text:<długość>]`, z wyjątkiem kluczy `title`, `label`, `*_title` i `*_label` (stałe etykiety UI i nazwy usług). Wartości query i parametrów trasy muszą być pojedynczym słowem do 40 znaków; `mask_params: ['*']` maskuje wszystkie.
- Maskowanie: klucze `Events::sensitiveKey()` (słowa w snake/camelCase, np. `password`, `api_key`, `csrf_token`, dokładne `code`, `state`) → `[x]`; parametry i query z `FREE_TEXT_PARAMS`/`mask_params` → `[x]`, numery 9–17 cyfr → `[num]`; teksty bez HTML, tokeny 16+ znaków z literą i cyfrą → `[tok]` (slugi z myślnikami zostają), e-mail → `[email]`, numery → `[num]`, do 200 znaków; klucze `id`/`*_id` zachowują identyfikatory; segment ścieżki 12+ znaków z cyfrą → `[x]`. Przychodzący `X-Request-ID` nie jest zaufany; odtwarzaj po aktorze i sesji.
- Analiza każdej aplikacji jednym skryptem: `bin/events stats DIR [--from --to --json]` i `bin/events replay DIR --actor=user:ID|--request=ID [--from --to]`.

## Kontrolery i Response

- `Controller` ma data bag `protected array $data` + `set()`/`get()`
- `Controller::render()` łączy data bag z danymi explicit oraz globalami (`flash`, `csrf`, `url`)
- `Response::sendAndExit()` wspiera legacy flow
- `SseResponse` obsługuje Server-Sent Events

## Bezpieczeństwo i obsługa błędów

- Globalny handler: ostrzeżenia → 500, fatale łapane przez shutdown handler
- Router zwraca `405 Method Not Allowed` z nagłówkiem `Allow`
- Regex trasy jest kompilowany dopiero przy dopasowaniu; trasy o innym literalnym prefiksie ASCII są odrzucane bez regexu
- `App::addSecurityHeaders()` — CSP, HSTS, XFO, XCTO, Referrer-Policy, Permissions-Policy
- `Request::fromGlobalsWithProxies()` + `trusted_proxies` — bezpieczne IP za proxy
- `max_request_body_bytes` ogranicza buforowane, zwykłe body; `max_multipart_body_bytes`
  ma osobny limit i domyślnie dziedziczy pierwszą wartość. Przekroczenie kończy się
  `413` przed middleware i dispatchem trasy
- limit aplikacyjny nie zastępuje limitów serwera WWW ani `post_max_size` / `upload_max_filesize`, szczególnie dla form i uploadów parsowanych przed kodem aplikacji
- `Session::regenerate()` — po logowaniu
- handler sesji implementuje `validateId()`; bez tego `session.use_strict_mode=1` nie odrzuca obcego ID
- timeout blokady sesji: `Session::read()` rzuca `SessionLockException` (503 + `Retry-After`), sesja w DB zostaje nietknięta. `App::startSession()` przed `handle()` zwraca `false` i odkłada 503 do najbliższego `handle()` (przed middleware, więc bez 403 z CSRF); w trakcie `handle()` rzuca wyjątek dalej. AJAX/`Accept: application/json` dostaje JSON `{success:false,message}`
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

bin/test profiles: `quick|full|ci|coverage|mutation|contracts|e2e|ui`
- `bin/test quick` — składnia + Unit + Integration
- `bin/test full` — quick + Contracts + Consumer copies + PHPStan
- `bin/test ci` — full + coverage z minimalnym pokryciem linii 85%; brak drivera kończy profil błędem
- `bin/test mutation` — izolowany Infection dla `src/PFrame.php`, domyślnie jeden wątek, PCOV/Xdebug i POSIX; instalacja: `composer install --working-dir=tools/infection`
- `composer test` = alias do `bin/test quick`

`src/PFrameTesting.php` zależy od PHPUnit i nie jest częścią runtime autoload. Konsument kopiuje
ten plik osobno i wymaga go jawnie w `tests/bootstrap.php` po `vendor/autoload.php`.

PHPUnit 13 nie obsługuje `-v`; gdy potrzebny jest szczegółowy przebieg, użyj `--debug`.

## Lokalne porty

PFrame nie uruchamia stałego lokalnego serwera HTTP. Port hosta `3306` należy
do usługi MySQL w GitHub Actions tego repozytorium. Kanoniczny przydział portów
wszystkich repozytoriów jest w `/home/pawel/dev/infra/local-ports.json`; nowy
stały listener najpierw zarejestruj w tym pliku.

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

Wydanie zmiany do konsumentów (bez ręcznego kopiowania):
```bash
./bin/release [--push] [konsument ...]   # bez nazw: wszyscy nieaktualni
```
Wymaga czystego drzewa i HEAD obecnego w `origin/main`, uruchamia `bin/test quick` i PHPStan
PFrame, a u każdego nieaktualnego konsumenta z czystym drzewem kopiuje pliki, zapisuje pełny SHA
wydanego commita w `lib/PFRAME_VERSION`, uruchamia bramkę konsumenta i commituje „Update PFrame to
<sha>”. Bramką jest `composer test:pframe`, jeśli konsument ma taki skrypt (Brazar: cały backend),
a w przeciwnym razie `composer test`. Błąd testów, odrzucenie commita przez hook lub
przerwanie cofa kopię; konsument z niezacommitowanymi zmianami (a przy `--push` bez upstreamu) jest pomijany. Deploy każdego konsumenta wykonuje się jego własną procedurą.
Każdy konsument musi mieć skrypt `composer test` albo `composer test:pframe`. `check-consumers.sh`
wypisuje zapisany `PFRAME_VERSION` informacyjnie; rozjazd nadal wykazuje wyłącznie porównanie plików.

## Gotchas

- `paginate()` zwraca `per_page`/`offset`, NIE `limit`
- `Response::statusCode()` — usunięty
- `$app->addMiddleware(...)` — NIE `$app->use(...)`
- `App::instance()` throws `LogicException` przy konflikcie klas
- `example/` jest w `.gitignore` — footgun przy demo
- Flash PRZED session clear — `session_regenerate_id(true)` nie `destroy()`
- `run()` i `sendAndExit()` zapisują i zamykają sesję przed wysłaniem odpowiedzi (wolny klient nie blokuje kolejnych żądań użytkownika) — zapis do `$_SESSION` w callbacku `SseResponse` ani w shutdown handlerze nie jest utrwalany
- Logout = POST + CSRF (nie GET)
- `$app->get()` nie `addRoute()` — sprawdzaj istniejące wzorce routingu
- Nested transactions w testach: `rollbackAll()` nie pojedynczy `rollback()`
- `TickTask::command()` uruchamia przez shell — `;` i `&&` wykonywane, wymaga allowlisty/escaping
- CSP: `style-src 'unsafe-inline'` wymagane (error pages, DebugBar); scripts bez `unsafe-inline`
- `trusted_proxies` = exact IPs lub resolvable hostnames (np. `infra_caddy`), nie CIDR
- Adresy nazw hostów z `trusted_proxies` są pamiętane w APCu przez 60 s i używane tylko wtedy, gdy zawierają `REMOTE_ADDR` żądania; inny adres wymusza świeże zapytanie DNS. Bez APCu nazwa jest rozwiązywana przy każdym żądaniu
- Cache: jeden backend per request (APCu-only gdy dostępny, file-only bez APCu); file backend ma trwałe, ograniczone stripe locki, których `clear()` nie usuwa
- `Cache::pruneExpired(1000)` uruchamiaj okresowo przez `Tick`/cron, bo nieodczytywane wygasłe pliki nie sprzątają się same
- OPcache preload: `require_once`, nie `opcache_compile_file`
- `Tick`: `tryLock()` = flock only; `between()` wspiera okna przez północ; `inTimeWindow(?string $now)` testowalny
- Gdy PHPStan nie rozpoznaje globalnego helpera z `namespace {}`, preferuj
  punktowe `@phpstan-ignore-next-line` zamiast komplikowania parsera docblocków.
- Test fallbacku `error_log()` musi snapshotować i przywracać statyczny stan
  loggera. Po ręcznym dodaniu testu od razu sprawdź unikalność nazwy `test...`.

## Konwencje i zakres

- Zachowuj 1TBS/K&R (otwierający nawias w tej samej linii) oraz polskie komunikaty użytkowe.
- Null-safe wrappery na funkcje PHP mają sufiks `S` (`trimS`, `countS`, `strtotimeS`). Nie twórz równoległej konwencji.
- `src/PFrame.php` jest źródłem prawdy. Przy zmianie SQL zaktualizuj testy, które celowo asertują literalne zapytania; po nieudanym patchu najpierw przeczytaj świeży diff i bieżący fragment pliku.
- Producentami kopii konsumenckich są `src/PFrame.php` i `src/PFrameTesting.php`; checker rekurencyjnie znajduje katalogi `lib/`, także w aplikacjach zagnieżdżonych w monorepozytoriach, bez ręcznych list ani hashy sterujących synchronizacją (`lib/PFRAME_VERSION` jest tylko śladem wydania).
- `example/` jest ignorowane przez Git. Jeśli świadomie zmieniasz demo, waliduj je osobno i nie zakładaj, że pojawi się w `git status`.

## Wiedza i stan pracy

- Ten rootowy `AGENTS.md` jest kanoniczną instrukcją.
- Dłuższe, zweryfikowane rozwiązanie umieść w dokumentacji tematycznej. Jeśli powstanie backlog, użyj jednego `tasks/TODO.md`.
- Nowy plan w `docs/plans/` musi mieć status `draft`, `approved`, `active`, `done` albo `superseded`. Nie zakładaj, że istniejący plan jest aktywny bez porównania z kodem.
