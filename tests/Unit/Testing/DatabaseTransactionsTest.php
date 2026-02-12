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
