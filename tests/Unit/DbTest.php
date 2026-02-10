<?php
declare(strict_types=1);

namespace P1\Tests\Unit;

use P1\Db;
use PHPUnit\Framework\TestCase;

class DbTest extends TestCase {
    private Db $db;

    protected function setUp(): void {
        $this->db = new Db(['dsn' => 'sqlite::memory:']);
        $this->db->exec('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)');
        $this->db->exec('INSERT INTO users (name, email) VALUES (?, ?)', ['Joe', 'joe@x.com']);
        $this->db->exec('INSERT INTO users (name, email) VALUES (?, ?)', ['Ann', 'ann@x.com']);
    }

    public function testVar(): void {
        $this->assertEquals(2, $this->db->var('SELECT COUNT(*) FROM users'));
    }

    public function testVarNull(): void {
        $this->assertNull($this->db->var('SELECT name FROM users WHERE id = ?', [999]));
    }

    public function testRow(): void {
        $this->assertSame('Joe', $this->db->row('SELECT * FROM users WHERE id = ?', [1])['name']);
    }

    public function testRowNull(): void {
        $this->assertNull($this->db->row('SELECT * FROM users WHERE id = ?', [999]));
    }

    public function testResults(): void {
        $rows = $this->db->results('SELECT * FROM users ORDER BY id');
        $this->assertCount(2, $rows);
    }

    public function testCol(): void {
        $this->assertSame(['Joe', 'Ann'], $this->db->col('SELECT name FROM users ORDER BY id'));
    }

    public function testExecReturnsAffectedRows(): void {
        $this->assertSame(1, $this->db->exec('UPDATE users SET name = ? WHERE id = ?', ['Bob', 1]));
    }

    public function testExecSelectReturnsArray(): void {
        $rows = $this->db->exec('SELECT * FROM users ORDER BY id');
        $this->assertIsArray($rows);
        $this->assertCount(2, $rows);
    }

    public function testInsertGetId(): void {
        $this->assertSame(3, $this->db->insertGetId('INSERT INTO users (name, email) VALUES (?, ?)', ['New', 'new@x.com']));
    }

    public function testTransactionRollback(): void {
        $this->db->begin();
        $this->db->exec('INSERT INTO users (name, email) VALUES (?, ?)', ['Tx', 'tx@x.com']);
        $this->db->rollback();
        $this->assertEquals(2, $this->db->var('SELECT COUNT(*) FROM users'));
    }

    public function testTransactionCommit(): void {
        $this->db->begin();
        $this->db->exec('INSERT INTO users (name, email) VALUES (?, ?)', ['Tx', 'tx@x.com']);
        $this->db->commit();
        $this->assertEquals(3, $this->db->var('SELECT COUNT(*) FROM users'));
    }

    public function testPlaceholders(): void {
        $this->assertSame('?, ?, ?', $this->db->placeholders([1, 2, 3]));
    }

    public function testStringParam(): void {
        $row = $this->db->row('SELECT * FROM users WHERE name = ?', 'Joe');
        $this->assertSame('Joe', $row['name']);
    }

    public function testPdoAccessor(): void {
        $this->assertInstanceOf(\PDO::class, $this->db->pdo());
    }

    public function testQueryLog(): void {
        $db = new Db(['dsn' => 'sqlite::memory:']);
        $this->assertSame(0, $db->queryCount());

        $db->exec('CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)');
        $db->exec('INSERT INTO t (id, name) VALUES (?, ?)', [1, 'Joe']);
        $db->var('SELECT COUNT(*) FROM t');

        $this->assertSame(3, $db->queryCount());
        $this->assertGreaterThan(0.0, $db->queryTime());

        $log = $db->queryLog();
        $this->assertCount(3, $log);
        $this->assertStringContainsString('CREATE TABLE', $log[0]['sql']);
        $this->assertIsFloat($log[0]['time']);
        $this->assertSame("INSERT INTO t (id, name) VALUES (1, 'Joe')", $log[1]['sql']);
        $this->assertStringContainsString('SELECT COUNT', $log[2]['sql']);
    }
}
