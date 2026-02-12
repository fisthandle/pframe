# Plan: PFrame Test Scaffolding

Data: 2026-02-12
Status: reviewed (Codex xhigh)

## Kontekst

Analiza testów w 3 projektach (ogloszenia, domownik, brat) ujawniła powtarzalny boilerplate:

| Wzorzec | ogloszenia | domownik | brat |
|---------|-----------|---------|------|
| Transaction rollback | begin/rollback | begin/rollback | DatabaseTransactions trait |
| DB assertions | assertDatabaseHas/Missing/Count | ręczne query | ręczne query |
| Session mocking | actingAs() | ręczne $_SESSION | brak |
| SQLite :memory: | MariaDB (ParaTest) | SQLite :memory: | Docker MariaDB |

Projekty kopiują PFrame.php do `lib/`. Test helpers działają tak samo — jeden plik `PFrameTesting.php` do skopiowania + require w bootstrap.

## Architektura

Nowy plik: `src/PFrameTesting.php`
- Namespace: `PFrame\Testing`
- Traity (composable) + TestCase (convenience)
- Projekty kopiują do `lib/PFrameTesting.php`, require w `tests/bootstrap.php`
- Zero nowych zależności (PHPUnit jest dev-dep projektu)
- **Autoload:** TYLKO `require` w bootstrap — NIE `autoload-dev.files` (unika double-load)

### W scope
- DatabaseTransactions trait
- DatabaseAssertions trait
- ActingAs trait
- TestCase base class (łączy traity, opinionated: **wymaga DB w bootstrap**)
- Testy samych helpers
- Dokumentacja filozofii testów

### Poza scope
- HTTP testing (ControllerTestCase) — za project-specific
- Factory methods — dane są domenowe
- TestDatabaseManager / schema init — per projekt
- ParaTest config — per projekt

## Zadania

### Task 1: Trait DatabaseTransactions

Plik: `src/PFrameTesting.php`

```php
<?php
declare(strict_types=1);

namespace PFrame\Testing;

use PFrame\Base;
use PHPUnit\Framework\TestCase as PHPUnitTestCase;

trait DatabaseTransactions {
    protected function setUpDatabaseTransactions(): void {
        Base::db()->begin();
    }

    protected function tearDownDatabaseTransactions(): void {
        if (Base::db()->trans()) {
            Base::db()->rollback();
        }
    }
}
```

Guard `trans()` w tearDown zapobiega podwójnemu rollback gdy test explicite robi rollback.

### Task 2: Trait DatabaseAssertions

Kontynuacja `src/PFrameTesting.php`:

```php
trait DatabaseAssertions {
    protected function assertDatabaseHas(string $table, array $conditions): void {
        [$where, $params] = $this->buildWhereClause($conditions);
        $row = Base::row("SELECT 1 FROM $table WHERE $where LIMIT 1", $params);
        $this->assertNotNull($row, "No row in '$table' matching " . json_encode($conditions));
    }

    protected function assertDatabaseMissing(string $table, array $conditions): void {
        [$where, $params] = $this->buildWhereClause($conditions);
        $row = Base::row("SELECT 1 FROM $table WHERE $where LIMIT 1", $params);
        $this->assertNull($row, "Unexpected row in '$table' matching " . json_encode($conditions));
    }

    protected function assertDatabaseCount(string $table, int $expected): void {
        $count = (int) Base::var("SELECT COUNT(*) FROM $table");
        $this->assertSame($expected, $count, "Expected $expected rows in '$table', got $count");
    }

    /** @return array{0: string, 1: list<mixed>} */
    private function buildWhereClause(array $conditions): array {
        if ($conditions === []) {
            return ['1=1', []];
        }
        $where = [];
        $params = [];
        foreach ($conditions as $col => $val) {
            if ($val === null) {
                $where[] = "$col IS NULL";
            } else {
                $where[] = "$col = ?";
                $params[] = $val;
            }
        }
        return [implode(' AND ', $where), $params];
    }
}
```

Uwagi (Codex review):
- `buildWhereClause([])` zwraca `'1=1'` zamiast pustego stringa — zapobiega invalid SQL
- NULL values generują `IS NULL` zamiast `= ?` z null param

### Task 3: Trait ActingAs

Kontynuacja `src/PFrameTesting.php`:

```php
trait ActingAs {
    protected function actingAs(array $user): void {
        $_SESSION['user'] = $user;
    }

    protected function actingAsGuest(): void {
        unset($_SESSION['user']);
    }
}
```

Konwencja PFrame: `$_SESSION['user']` trzyma dane zalogowanego użytkownika. Używane w `Controller::currentUser()` (src/PFrame.php:1449), `Controller::isAuthenticated()` (src/PFrame.php:1457).

### Task 4: TestCase base class

Kontynuacja `src/PFrameTesting.php`:

```php
class TestCase extends PHPUnitTestCase {
    use DatabaseTransactions, DatabaseAssertions, ActingAs;

    protected function setUp(): void {
        parent::setUp();
        $_SESSION = [];
        $this->setUpDatabaseTransactions();
    }

    protected function tearDown(): void {
        $this->tearDownDatabaseTransactions();
        $_SESSION = [];
        parent::tearDown();
    }
}
```

**Precondition:** TestCase wymaga DB skonfigurowane w bootstrap (`new App()` + `setDb()`). Projekty bez DB używają traits bezpośrednio na `PHPUnit\Framework\TestCase`.

### Task 5: Update PFrame's test bootstrap

Plik: `tests/bootstrap.php`

```php
<?php
declare(strict_types=1);
define('TESTING', true);
require dirname(__DIR__) . '/vendor/autoload.php';
require dirname(__DIR__) . '/src/PFrameTesting.php';
```

TYLKO `require` — bez `autoload-dev.files` (Codex: unika double-load gdy Composer już ładuje files z autoload).

### Task 6: Test DatabaseTransactions trait

Plik: `tests/Unit/Testing/DatabaseTransactionsTest.php`

```php
<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit\Testing;

use PFrame\App;
use PFrame\Db;
use PFrame\Base;
use PFrame\Testing\DatabaseTransactions;
use PHPUnit\Framework\TestCase;

class DatabaseTransactionsTest extends TestCase {
    use DatabaseTransactions;

    protected function setUp(): void {
        parent::setUp();
        $app = new App();
        $db = new Db(['dsn' => 'sqlite::memory:']);
        $db->exec('CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)');
        $db->exec('INSERT INTO items (name) VALUES (?)', ['seed']);
        $app->setDb($db);
        $this->setUpDatabaseTransactions();
    }

    protected function tearDown(): void {
        $this->tearDownDatabaseTransactions();
        parent::tearDown();
    }

    public function testChangesAreRolledBack(): void {
        Base::exec('INSERT INTO items (name) VALUES (?)', ['temp']);
        $this->assertSame(2, (int) Base::var('SELECT COUNT(*) FROM items'));

        $this->tearDownDatabaseTransactions();

        // After rollback, seed data survives, temp is gone
        $this->assertSame(1, (int) Base::var('SELECT COUNT(*) FROM items'));

        // Re-begin for tearDown
        $this->setUpDatabaseTransactions();
    }

    public function testTearDownSafeWhenAlreadyRolledBack(): void {
        Base::db()->rollback();
        // tearDown should not throw — trans() guard handles this
        $this->assertTrue(true);
    }
}
```

Rollback proof w jednym test method — nie zależy od kolejności testów (Codex: PHPUnit wspiera random order).

### Task 7: Test DatabaseAssertions trait

Plik: `tests/Unit/Testing/DatabaseAssertionsTest.php`

```php
<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit\Testing;

use PFrame\App;
use PFrame\Db;
use PFrame\Testing\DatabaseAssertions;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\TestCase;

class DatabaseAssertionsTest extends TestCase {
    use DatabaseAssertions;

    protected function setUp(): void {
        parent::setUp();
        $app = new App();
        $db = new Db(['dsn' => 'sqlite::memory:']);
        $db->exec('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)');
        $db->exec('INSERT INTO users (name, email) VALUES (?, ?)', ['Joe', 'joe@x.com']);
        $db->exec('INSERT INTO users (name, email) VALUES (?, ?)', ['Ann', null]);
        $app->setDb($db);
    }

    public function testAssertDatabaseHas(): void {
        $this->assertDatabaseHas('users', ['name' => 'Joe', 'email' => 'joe@x.com']);
    }

    public function testAssertDatabaseHasFails(): void {
        $this->expectException(AssertionFailedError::class);
        $this->assertDatabaseHas('users', ['name' => 'Nobody']);
    }

    public function testAssertDatabaseMissing(): void {
        $this->assertDatabaseMissing('users', ['name' => 'Nobody']);
    }

    public function testAssertDatabaseMissingFails(): void {
        $this->expectException(AssertionFailedError::class);
        $this->assertDatabaseMissing('users', ['name' => 'Joe']);
    }

    public function testAssertDatabaseCount(): void {
        $this->assertDatabaseCount('users', 2);
    }

    public function testAssertDatabaseCountFails(): void {
        $this->expectException(AssertionFailedError::class);
        $this->assertDatabaseCount('users', 99);
    }

    public function testAssertDatabaseHasWithNull(): void {
        $this->assertDatabaseHas('users', ['name' => 'Ann', 'email' => null]);
    }

    public function testAssertDatabaseMissingWithNull(): void {
        $this->assertDatabaseMissing('users', ['name' => 'Joe', 'email' => null]);
    }

    public function testAssertDatabaseHasWithEmptyConditions(): void {
        // Empty conditions = match any row (WHERE 1=1)
        $this->assertDatabaseHas('users', []);
    }
}
```

Codex: dodano test empty conditions.

### Task 8: Test ActingAs trait

Plik: `tests/Unit/Testing/ActingAsTest.php`

```php
<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit\Testing;

use PFrame\Testing\ActingAs;
use PHPUnit\Framework\TestCase;

class ActingAsTest extends TestCase {
    use ActingAs;

    protected function setUp(): void {
        parent::setUp();
        $_SESSION = [];
    }

    public function testActingAsSetsUser(): void {
        $this->actingAs(['id' => 1, 'name' => 'Joe']);
        $this->assertSame(['id' => 1, 'name' => 'Joe'], $_SESSION['user']);
    }

    public function testActingAsGuestRemovesUser(): void {
        $this->actingAs(['id' => 1, 'name' => 'Joe']);
        $this->actingAsGuest();
        $this->assertArrayNotHasKey('user', $_SESSION);
    }
}
```

### Task 9: Test TestCase integration

Plik: `tests/Unit/Testing/TestCaseIntegrationTest.php`

```php
<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit\Testing;

use PFrame\App;
use PFrame\Db;
use PFrame\Base;
use PFrame\Testing\TestCase;

class TestCaseIntegrationTest extends TestCase {
    protected function setUp(): void {
        $app = new App();
        $db = new Db(['dsn' => 'sqlite::memory:']);
        $db->exec('CREATE TABLE items (id INTEGER PRIMARY KEY, val TEXT)');
        $db->exec('INSERT INTO items (val) VALUES (?)', ['seed']);
        $app->setDb($db);
        parent::setUp(); // calls setUpDatabaseTransactions
    }

    public function testTransactionAndAssertions(): void {
        Base::exec('INSERT INTO items (val) VALUES (?)', ['new']);
        $this->assertDatabaseHas('items', ['val' => 'new']);
        $this->assertDatabaseCount('items', 2);
        $this->assertDatabaseMissing('items', ['val' => 'nope']);
    }

    public function testActingAsIntegrated(): void {
        $this->actingAs(['id' => 5, 'role' => 'admin']);
        $this->assertSame(5, $_SESSION['user']['id']);
    }

    public function testSessionResetBetweenTests(): void {
        $this->assertEmpty($_SESSION);
    }
}
```

### Task 10: Dokumentacja filozofii testów

Plik: `docs/testing-philosophy.md`

```markdown
# Filozofia testów

## Zasady

1. **Szybkość** — SQLite :memory: dla unit/smoke, MySQL/MariaDB dla integration
2. **Izolacja** — transaction rollback (begin w setUp, rollback w tearDown)
3. **Czytelność** — assertions czytają stan DB, nie testują implementacji
4. **Composable** — traity zamiast monolitycznej base class
5. **Zero boilerplate** — PFrame dostarcza TestCase, projekt dodaje factory methods

## Struktura testów

    tests/
    ├── bootstrap.php       ← App, DB, schema setup + require PFrameTesting.php
    ├── TestCase.php         ← extends PFrame\Testing\TestCase + project factories
    ├── Unit/                ← pure logic, no HTTP
    ├── Integration/         ← full request cycle
    └── fixtures/            ← config, templates, SQL

## PFrame\Testing\TestCase

Łączy 3 traity: DatabaseTransactions, DatabaseAssertions, ActingAs.
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
```

### Task 11: Weryfikacja

```bash
vendor/bin/phpunit tests/Unit/Testing/
vendor/bin/phpunit  # pełny suite — regresja
```

## Kolejność

1. Task 1-4: `src/PFrameTesting.php` (traity + TestCase) — jeden plik
2. Task 5: bootstrap update
3. Task 6-9: testy
4. Task 11: weryfikacja
5. Task 10: dokumentacja

## Codex review feedback (zastosowane)

- [x] Autoload: TYLKO require w bootstrap, bez autoload-dev.files (double-load risk)
- [x] Empty conditions: `buildWhereClause([])` zwraca `'1=1'` + test
- [x] Broken Base::row() variant: usunięty, zostawiony tylko buildWhereClause
- [x] Test ordering: rollback proof w jednym method, nie cross-test
- [x] PHPUnit exception: `AssertionFailedError` potwierdzone (PHPUnit 11)
- [x] DB precondition: explicite w Task 4 — TestCase wymaga DB w bootstrap
