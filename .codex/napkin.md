# Napkin — PFrame

Czytaj selektywnie przy zmianach core, SQL, cache, Tick lub testów.

## Korekty i pułapki

- PHPStan nie zawsze respektuje phpdoc globalnych helperów z `namespace {}`; dla pojedynczego, uzasadnionego przypadku użyj `@phpstan-ignore-next-line` zamiast komplikować parser docblocków.
- PHPUnit 11.5 nie ma `-v`; użyj zwykłego uruchomienia albo `--debug`.
- Testy asertują część SQL literalnie. Po zmianie quoting lub tekstu zapytania zaktualizuj odpowiadającą asercję.
- `example/` jest ignorowane. Waliduj zmienione pliki demo przez `php -l`, nawet gdy status jest czysty.
- Fallback throttle powinien trzymać timestamp w pliku pod `flock`; `filemtime()` blokował pierwszy dispatch.
- Cache wybiera jeden backend na request: APCu-only, gdy dostępne, albo file-only. Dual-read zwracał stare dane z pliku po miss w APCu.
- Testy fallbacku `error_log()` muszą snapshotować i przywracać statyczny stan loggera, np. przez `ReflectionProperty`.
- Po ręcznym dopisaniu testu sprawdź od razu unikalność nazwy `test...`; duplikat funkcji ujawniał się dopiero w pełnym quick run.
- Po nieudanym `apply_patch` nie zgaduj stanu `src/PFrame.php`: najpierw `git diff -- src/PFrame.php` i świeży odczyt fragmentu.

## Sprawdzone wzorce

- Jednorazowy probe ładuje `src/PFrame.php` raz przez `require_once`, a dopiero potem wykonuje wiele wywołań.
- Naming review helperów zaczynaj od lokalnego słownika (`assertX`, `withX`, `asX`); nie zgłaszaj nazw zgodnych z wewnętrznym DSL jako samodzielnego problemu.
