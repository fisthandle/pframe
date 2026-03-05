# Napkin - PFrame

## Corrections
| Date | Source | What Went Wrong | What To Do Instead |
|------|--------|----------------|-------------------|
| 2026-02-10 | codex | `session_destroy()` before flash kills message | Flash BEFORE session clear. Use `session_regenerate_id(true)` not destroy. |
| 2026-02-10 | codex | Logout as GET without CSRF | Logout must be POST + CSRF, inline form in nav |
| 2026-02-18 | self | Sync agent modified PFrame.php outside scope | Give strict scope: "copy, test, report. Do NOT modify PFrame.php or consumer code." |
| 2026-02-18 | self | Tests used `addRoute()` and wrong db access patterns | Check existing patterns: `$app->get()` not `addRoute()`, `$this->db` not `$this->app->db()` |
| 2026-02-21 | self | Tymczasowy config PHPStan w `/tmp` użył ścieżki relatywnej `src/` i analiza padła | W configu poza repo zawsze używaj ścieżek absolutnych (np. `/home/pawel/dev/pframe/src`) |
| 2026-02-21 | self | PHPStan nie uwzględnił phpdoc typów dla globalnych helperów (`ha/getS/explodeS`) w `namespace {}` | Dla pojedynczych helperów użyj lokalnych `@phpstan-ignore-next-line` zamiast tracić czas na walkę z parserem docblocków |
| 2026-02-21 | self | Uruchomiłem `phpunit -v`, ale w PHPUnit 11.5.52 to nieobsługiwana flaga | Używaj `phpunit` bez `-v` (lub `--debug` gdy potrzebny szczegółowy output) |
| 2026-02-21 | self | Po dodaniu quoting w `batchInsert()` test liczący SQL log szukał starego prefiksu (`INSERT INTO bulk`) | Przy zmianach SQL aktualizuj asercje testów opartych o literalny tekst zapytań |
| 2026-02-21 | self | Jednolinijkowy `php -r` z `$e->...` w podwójnym cudzysłowie złamał się przez ekspansję shella | Dla snippetów z `$` używaj apostrofów wokół całego kodu PHP |
| 2026-02-21 | self | Usunięcie `instanceof static` w `App::instance()` spowodowało TypeError przy wywołaniu przez subclassę | Zamiast cichej podmiany instancji rzucaj jawny `LogicException` przy konflikcie klasy singletona |
| 2026-02-23 | self | Po zmianie error page na HTML testy szukały jednego stringa `404 Not Found` i padały | W asercjach HTML sprawdzaj osobno kod (`404`) i tekst (`Not Found`), bo są w osobnych elementach |
| 2026-02-23 | self | W tym repo `example/` jest ignorowany przez git (`git ls-files example` puste) | Zmiany w `example/*` waliduj `php -l` i komunikuj userowi, że nie pojawią się w `git status` |
| 2026-02-24 | self | Szukałem `tasks/TODO.md` w `pframe`, ale playbook jest w `/home/pawel/dev/tasks/TODO.md` | Przy zadaniach cross-repo najpierw sprawdź globalne `~/dev/tasks/TODO.md`, potem lokalne `repo/tasks` |
| 2026-02-24 | self | `full` padł na PHPStan przez `proc_open($this->cmd, ...)` z możliwym `null` | W `TickTask::executeCommand()` najpierw zrób lokalny guard `$command === null` i dopiero wywołaj `proc_open()` |
| 2026-02-25 | self | Planowa allowlista schematu oparta wyłącznie na `parse_url()` nie wyłapie schematów zaczynających się od whitespace lub zakodowanego dwukropka („ javascript:alert”/„javascript%3Aalert”) | Przy redirectach najpierw trimuj/dekoduj dane wejściowe albo odrzucaj bezpiecznie schematy zaczynające się od `:`/spacji przed wywołaniem `parse_url()` |
| 2026-02-25 | self | Throttle fallback oparty o `filemtime()` blokował pierwszy dispatch po utworzeniu pliku locka | W fallbacku throttle trzymaj ostatni timestamp bezpośrednio w pliku i czytaj go pod `flock`, nie opieraj logiki na samym mtime |
| 2026-02-26 | self | `Cache` robił dual-write (APCu + plik), a `get()` przy braku klucza w APCu wpadał do pliku i zwracał stare dane | W `Cache` wybieraj jeden backend per request: APCu-only gdy dostępny, file-only jako fallback bez APCu; bez mieszania źródeł |
| 2026-02-26 | self | `Cache` przestał robić auto-`mkdir`; testy które używają świeżej ścieżki zaczynają padać | Przy setupie testów jawnie twórz katalog cache (`mkdir(...)`) albo używaj `new Cache()` w trybie APCu-only |
| 2026-03-05 | self | Szeroki `rg` bez zawężenia złapał artefakty (`tests/_artifacts`) i zwrócił gigantyczny output blokowany przez sandbox | Przy audytach zawsze zawężaj scope do katalogów kodu (`app`, `public`, `docker`) albo używaj `-g` z wykluczeniami dla artefaktów/logów |
| 2026-03-05 | self | `rg` potraktował wzorzec `->begin` jako flagę CLI (`unrecognized flag ->`) | Przy wzorcach zaczynających się od `-` zawsze używaj `rg -- 'pattern' ...` |
| 2026-03-05 | self | Ustawiłem `-g '*.php'` po ścieżkach w `rg`, więc flaga została potraktowana jak path (`rg: -g: No such file or directory`) | W `rg` wszystkie opcje (`--glob`, `--hidden`, itp.) podawaj przed listą ścieżek |
| 2026-03-05 | self | W audycie security łatwo przeoczyć, że `parse_url()` nie traktuje `http:evil.com` i `\\evil.com` jak klasycznego hosta, więc guard hosta nie zadziała | W redirectach waliduj URL przez parser WHATWG lub regex allowlistę dla ścieżek lokalnych (`/…`) i blokuj backslash + schemat bez `//` |
| 2026-03-05 | self | Plan fixów redirectu obejmował tylko backslash, pomijając payload `http:evil.com` (scheme bez `//`) | Przy hardeningu redirectów zawsze testuj oba bypassy: backslash (`/\\evil.com`) i `http:evil.com` |
| 2026-03-05 | codex | Plan intended-url-after-login wymagał serii korekt z code review | GET/HEAD guard na intent URL; stała `Session::INTENDED_URL_KEY` zamiast magic string; query string budowany jak `App::url()` z check `$qs !== ''`; testy w istniejący plik (nie osobny); task order (Session→Middleware); `bin/test quick` pre-commit; consumer example z `App::instance()->url()` |
| 2026-03-05 | codex | Plan audit-fixes wymagał korekt w Task 3-7 po Codex review | Task 3: dodaj `use PFrame\Csrf;` import, użyj istniejącej route `/json` bez duplikatu; Task 4: DB config `['dsn' => 'sqlite::memory:', 'log_queries' => true]` (nie `driver/database`); Task 5: `renderFilesList()` przyjmuje `$d` bez podwójnego `toArray()`; Task 6: `dsn` w configu, `log_queries: true` w testach, lekki `UPDATE stamp` zamiast pełnego skip-write (zachowuje TTL/GC), early return w `try/finally`, lock timeout default `30`; Task 7: path `tests/TickTest.php` (nie `tests/Unit`), API `$tick->task()->command()->execute()`, `proc_terminate` safety net, zamykanie pipes przed `proc_close()` |

## User Preferences
- 1TBS brace style
- Polish error messages (Wymagane logowanie, Brak dostępu, etc.)
- Null-safe helpers use `functionNameS()` convention (trimS, countS, etc.)
- Audyty performance: tylko realne bottlenecks z dowodem `file:line`, raport severity-first + sekcje cross-cutting i quick wins.

- `docs/plans/2026-02-25-tick-hardening.md` captures the six-step Tick hardening rollout, covering midnight windows, throttle + prefix, file locks, retry count, docs, and final verification.

## Domain Notes
- `Tick::tryLock()` działa wyłącznie na lockach plikowych (`flock`), bez APCu TTL.
- `Tick` konstruktor przyjmuje `throttleSeconds` (domyślnie `30`) i `prefix` (domyślnie `md5(cacheDir)`).
- Nieudane taski Tick retryują do `maxRetries` (domyślnie `3`), potem scheduler czeka pełny interwał.
- `between()` wspiera okna przechodzące przez północ, np. `23:00-02:00`.
- `TickTask::inTimeWindow(?string $now)` ma wstrzykiwalny czas do testów deterministycznych.
- `DatabaseTransactions::tearDownDatabaseTransactions()` robi tylko pojedynczy `rollback()`, więc przy zagnieżdżonych transakcjach (savepointach) może zostawić aktywną transakcję; helper testowy powinien używać `rollbackAll()`.

## Session Notes
- Error pages: `handle()`/`handleHttpException()`/`handleException()` w `src/PFrame.php` — brak `setErrorPageHandler`.
- Example app: domyślne dane logowania, brak throttlingu logowania, `HttpTestingJsonCtrl::store` bypass CSRF.
- Limit równoległych subagentów: 6; zamykaj zakończonych przed spawn.
- 2026-03-05: Audyt simplification najstabilniej robić przez szybkie metryki `token_get_all` (długość + decision points) na `src/PFrame.php` przed czytaniem hotspotów; skraca czas i lepiej priorytetyzuje ROI.

- 2026-02-26: `./bin/test ci` completed all stages green (syntax, unit, integration, contracts, phpstan, coverage); `[SESSION] Refused write without advisory lock ...` appears as expected test log line, not a failure.
- 2026-03-05: `Response::redirect()` przepuszcza payloady `http:evil.com`, `\\evil.com` i `"/\\evil.com"`; parser URL po stronie klienta potrafi znormalizować je do zewnętrznego hosta.
- 2026-03-05: `TickTask::command()` uruchamia string przez shell (`proc_open`), więc separatory (`;`, `&&`) są wykonywane; traktować to jako sink wymagający allowlisty/arg escaping po stronie aplikacji.
- 2026-03-05: Przy audytach cross-repo ograniczaj `rg` do `--glob '*.php'` + wykluczenia (`!vendor/**`, `!.git/**`, `!public/js/**`), bo szeroki skan generuje szum i utrudnia znalezienie realnych findings.
- 2026-03-05: `docs/plans/2026-03-05-audit-fixes.md` wdrożone end-to-end z rozszerzeniem Task 1 (blokada `http:evil.com`); `bin/test quick` zielony.
