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

trait ActingAs {
    protected function actingAs(array $user): void {
        $_SESSION['user'] = $user;
    }

    protected function actingAsGuest(): void {
        unset($_SESSION['user']);
    }
}

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
