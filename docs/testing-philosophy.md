# Filozofia testów

## Zasady

1. **Szybkość** — SQLite `:memory:` dla unit/smoke; realne SQLite i MySQL dla kontraktów schematu
2. **Izolacja** — `PFrame\Testing\TestCase` robi transaction rollback (begin w setUp, rollback w tearDown); zwykły `PHPUnit\TestCase` nie ma automatycznego rollbacku
3. **Czytelność** — assertions czytają stan DB, nie testują implementacji
4. **Composable** — traity zamiast monolitycznej base class
5. **Zero boilerplate** — PFrame dostarcza TestCase, projekt dodaje factory methods

## Standard testowy v1 (runner contract)

Jedyny runner: `./bin/test <profile>`.

| Profil | Zakres |
|-------|--------|
| `quick` | syntax + `Unit` + `Integration` |
| `full` | `quick` + `Contracts` + kontrola kopii konsumenckich + `phpstan` |
| `ci` | `full` + coverage report, minimum 85% pokrycia linii |
| `coverage` | phpunit z coverage artifacts (`build/coverage`), minimum 85% pokrycia linii |
| `contracts` | governance runnera i testy kontraktowe |
| `e2e`/`ui` | w repo frameworka N/A (czytelny komunikat + exit 2) |

`composer test`, `test:quick`, `test:full`, `test:ci` i `test:coverage` wywołują profile runnera
(`composer test` = `./bin/test quick`). `test:unit`, `test:integration` i `test:contracts` uruchamiają
bezpośrednio wskazaną suitę PHPUnit; `bin/test contracts` dodatkowo sprawdza kopie konsumenckie.
CI uruchamia dokładnie `./bin/test ci`, bez duplikowania kroków w workflow.

Profile `coverage` i `ci` wymagają drivera (`xdebug`, `pcov` lub `phpdbg`) i kończą się błędem,
gdy raport nie powstał albo pokrycie linii spadło poniżej 85%.

## Struktura testów u konsumenta

    tests/
    ├── bootstrap.php       ← App, DB, schema setup + require PFrameTesting.php
    ├── TestCase.php         ← extends PFrame\Testing\TestCase + project factories
    ├── Unit/                ← pure logic, no HTTP
    ├── Integration/         ← full request cycle
    ├── Contracts/           ← wykonywalne kontrakty runnera i narzędzi repo
    └── fixtures/            ← config, templates, SQL

## PFrame\Testing\TestCase

Łączy 6 traitów: DatabaseTransactions, DatabaseAssertions, ActingAs, ResponseAssertions, FlashAssertions, SessionAssertions.
**Wymaga** DB skonfigurowane w bootstrap.

`PFrameTesting.php` zależy od PHPUnit, dlatego konsument wymaga go jawnie po `vendor/autoload.php`;
nie jest ładowany przez runtime Composer.

Automatyczny rollback transakcji dotyczy wyłącznie klas dziedziczących po `PFrame\Testing\TestCase`.
Testy oparte bezpośrednio na `PHPUnit\TestCase` muszą zapewnić własną izolację.

Projekty bez DB używają poszczególnych traitów na PHPUnit\TestCase.

## Transaction rollback

Test dziedziczący po `PFrame\Testing\TestCase` działa w transakcji. `tearDown()` robi rollback —
dane z testu nie przenikają do następnego. Zwykły `PHPUnit\TestCase` nie dostaje tego mechanizmu.

    class MyTest extends TestCase {
        public function testCreateUser(): void {
            $this->createUser(['name' => 'Joe']);
            $this->assertDatabaseHas('users', ['name' => 'Joe']);
            // rollback w tearDown — Joe znika
        }
    }

## DB assertions

    $this->assertDatabaseHas('users', ['email' => 'joe@x.com']);
    $this->assertDatabaseMissing('users', ['email' => 'gone@x.com']);
    $this->assertDatabaseCount('users', 5);
    $this->assertDatabaseHas('users', ['email' => null]);  // IS NULL

## Session mocking

    $this->actingAs(['id' => 1, 'name' => 'Joe', 'role' => 'admin']);
    $this->actingAsGuest();

## HTTP Testing

    class UserTest extends \PFrame\Testing\TestCase {
        use \PFrame\Testing\HttpTesting;

        protected App $app;

        protected function setUp(): void {
            parent::setUp();
            $this->app = new App();
            // register routes...
        }

        public function testUserList(): void {
            $this->get('/users');
            $this->assertOk();
            $this->assertSee('Users');
        }

        public function testCreateUser(): void {
            $this->actingAs(['id' => 1, 'role' => 'admin']);
            $this->post('/users', ['name' => 'Joe', 'email' => 'joe@x.com']);
            $this->assertRedirectTo('/users');
            $this->assertFlash('success', 'User created');
            $this->assertDatabaseHas('users', ['email' => 'joe@x.com']);
        }
    }

CSRF jest wstrzykiwany automatycznie do POST/PUT/PATCH/DELETE.
Opt-out: `$this->withoutCsrf()->post(...)`.

Każde wywołanie HTTP zeruje diagnostykę requestu i DB, ale zachowuje aktywną transakcję testową
oraz jej savepointy. `commit()` wewnętrznej transakcji nie zatwierdza transakcji całego testu.

## Response assertions

    $this->assertOk();                           // status 200
    $this->assertNotFound();                     // status 404
    $this->assertForbidden();                    // status 403
    $this->assertUnauthorized();                 // status 401
    $this->assertStatus(201);                    // exact status
    $this->assertRedirect();                     // 3xx
    $this->assertRedirectTo('/login');           // 3xx + Location header
    $this->assertSee('Welcome');                 // body contains
    $this->assertDontSee('Error');               // body does not contain
    $this->assertJsonContains(['success' => true]);      // JSON subset match
    $this->assertHeader('Content-Type', 'application/json');
    $this->assertHeaderMissing('X-Debug');

## Flash assertions

    $this->assertFlash('success', 'Saved');      // type + text
    $this->assertFlash('error');                 // type only
    $this->assertNoFlash('error');               // no flash of type
    $this->assertNoFlash();                      // no flash at all

## Session assertions

    $this->assertAuthenticated();                // $_SESSION['user'] set
    $this->assertGuest();                        // $_SESSION['user'] empty
    $this->assertSessionHas('locale', 'pl');     // key + value
    $this->assertSessionHas('cart');             // key only
    $this->assertSessionMissing('temp');         // key absent

## RefreshDatabase

Trait do automatycznego ładowania migracji z katalogu SQL. Migracje są wykonywane raz na parę
`PDO` + ścieżka migracji (nie per test).

    class TestCase extends \PFrame\Testing\TestCase {
        use \PFrame\Testing\RefreshDatabase;

        protected function migrationPath(): string {
            return __DIR__ . '/../db/migrations';
        }

        protected function setUp(): void {
            $this->bootRefreshDatabase();  // przed parent::setUp() (przed begin())
            parent::setUp();
        }
    }

## Composable traity

| Trait | Wymaga | W TestCase |
|-------|--------|------------|
| DatabaseTransactions | Base::db() | ✅ |
| DatabaseAssertions | Base::db() | ✅ |
| ActingAs | — | ✅ |
| ResponseAssertions | $this->response | ✅ |
| FlashAssertions | $_SESSION | ✅ |
| SessionAssertions | $_SESSION | ✅ |
| HttpTesting | $this->app (App) | ❌ (wymaga config) |
| RefreshDatabase | Base::db() + migrationPath() | ❌ (wymaga config) |

## Factory methods (per projekt)

PFrame NIE dostarcza factory methods — dane są domenowe. Projekt definiuje je w swoim TestCase:

    class TestCase extends \PFrame\Testing\TestCase {
        protected function createUser(array $overrides = []): int {
            $data = array_merge(['name' => 'Test', 'email' => 'test@x.com'], $overrides);
            return Base::insertGetId(
                'INSERT INTO users (name, email) VALUES (?, ?)',
                [$data['name'], $data['email']]
            );
        }
    }

## Kiedy SQLite, kiedy MySQL

| Typ testu | Baza | Powód |
|-----------|------|-------|
| Unit | SQLite :memory: | Szybkość, zero setup |
| Smoke | SQLite :memory: | Szybkość, zero setup |
| Integration HTTP/worker | SQLite `:memory:` | Izolowany pełny lifecycle requestu |
| Schema contract | SQLite + MySQL 8.4 w CI | Wykonanie dostarczonych DDL i realny lifecycle sesji |

## Parallel testing (opcjonalne)

ParaTest z per-worker bazami: DB_NAME=app_test_{TEST_TOKEN}. Wymaga TestDatabaseManager — project-specific.
