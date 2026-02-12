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
        parent::setUp();
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
