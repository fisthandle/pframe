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
        $this->assertDatabaseHas('users', []);
    }
}
