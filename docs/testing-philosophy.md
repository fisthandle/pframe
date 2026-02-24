# Filozofia testów

## Zasady

1. **Szybkość** — SQLite :memory: dla unit/smoke, MySQL/MariaDB dla integration
2. **Izolacja** — transaction rollback (begin w setUp, rollback w tearDown)
3. **Czytelność** — assertions czytają stan DB, nie testują implementacji
4. **Composable** — traity zamiast monolitycznej base class
5. **Zero boilerplate** — PFrame dostarcza TestCase, projekt dodaje factory methods

## Standard testowy v1 (runner contract)

Jedyny runner: `./bin/test <profile>`.

| Profil | Zakres |
|-------|--------|
| `quick` | syntax + `Unit` + `Integration` |
| `full` | `quick` + `Contracts` + `phpstan` |
| `ci` | `full` + coverage report |
| `coverage` | phpunit z coverage artifacts (`build/coverage`) |
| `contracts` | governance runnera i testy kontraktowe |
| `e2e`/`ui` | w repo frameworka N/A (czytelny komunikat + exit 0) |

Komendy `composer test*` są aliasami do tego kontraktu (`composer test` = `./bin/test quick`).
CI uruchamia dokładnie `./bin/test ci`, bez duplikowania kroków w workflow.

Gdy środowisko nie ma drivera coverage (`xdebug`, `pcov` lub `phpdbg`), profile `coverage` i `ci`
wypisują komunikat o fallbacku i kończą się sukcesem, zamiast przerywać cały pipeline.

## Struktura testów

    tests/
    ├── bootstrap.php       ← App, DB, schema setup + require PFrameTesting.php
    ├── TestCase.php         ← extends PFrame\Testing\TestCase + project factories
    ├── Unit/                ← pure logic, no HTTP
    ├── Integration/         ← full request cycle
    └── fixtures/            ← config, templates, SQL

## PFrame\Testing\TestCase

Łączy 6 traitów: DatabaseTransactions, DatabaseAssertions, ActingAs, ResponseAssertions, FlashAssertions, SessionAssertions.
**Wymaga** DB skonfigurowane w bootstrap.

Projekty bez DB używają poszczególnych traitów na PHPUnit\TestCase.

## Transaction rollback

Każdy test działa w transakcji. tearDown robi rollback — dane z testu nie przenikają do następnego.

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

Trait do automatycznego ładowania migracji z katalogu SQL. Raz per proces (nie per test).

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
| Integration | MySQL/MariaDB | Zgodność z produkcją |

## Parallel testing (opcjonalne)

ParaTest z per-worker bazami: DB_NAME=app_test_{TEST_TOKEN}. Wymaga TestDatabaseManager — project-specific.
