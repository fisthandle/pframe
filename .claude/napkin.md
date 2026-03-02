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

## User Preferences
- 1TBS brace style
- Polish error messages (Wymagane logowanie, Brak dostępu, etc.)
- Null-safe helpers use `functionNameS()` convention (trimS, countS, etc.)

- `docs/plans/2026-02-25-tick-hardening.md` captures the six-step Tick hardening rollout, covering midnight windows, throttle + prefix, file locks, retry count, docs, and final verification.

## Domain Notes
- `Tick::tryLock()` działa wyłącznie na lockach plikowych (`flock`), bez APCu TTL.
- `Tick` konstruktor przyjmuje `throttleSeconds` (domyślnie `30`) i `prefix` (domyślnie `md5(cacheDir)`).
- Nieudane taski Tick retryują do `maxRetries` (domyślnie `3`), potem scheduler czeka pełny interwał.
- `between()` wspiera okna przechodzące przez północ, np. `23:00-02:00`.
- `TickTask::inTimeWindow(?string $now)` ma wstrzykiwalny czas do testów deterministycznych.

## Session Notes
- Error pages: `handle()`/`handleHttpException()`/`handleException()` w `src/PFrame.php` — brak `setErrorPageHandler`.
- Example app: domyślne dane logowania, brak throttlingu logowania, `HttpTestingJsonCtrl::store` bypass CSRF.
- Limit równoległych subagentów: 6; zamykaj zakończonych przed spawn.

- 2026-02-26: `./bin/test ci` completed all stages green (syntax, unit, integration, contracts, phpstan, coverage); `[SESSION] Refused write without advisory lock ...` appears as expected test log line, not a failure.
