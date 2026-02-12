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
