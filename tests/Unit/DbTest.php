<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PFrame\Db;
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

    public function testExecSelectWithLeadingComment(): void {
        $rows = $this->db->exec("-- comment\nSELECT * FROM users ORDER BY id");
        $this->assertIsArray($rows);
        $this->assertCount(2, $rows);
    }

    public function testExecSelectWithCte(): void {
        $rows = $this->db->exec('WITH cte AS (SELECT * FROM users) SELECT * FROM cte');
        $this->assertIsArray($rows);
        $this->assertCount(2, $rows);
    }

    public function testExecSelectWithMultipleCtes(): void {
        $rows = $this->db->exec('WITH a AS (SELECT * FROM users), b AS (SELECT * FROM a) SELECT * FROM b');
        $this->assertIsArray($rows);
        $this->assertCount(2, $rows);
    }

    public function testInsertGetId(): void {
        $this->assertSame(3, $this->db->insertGetId('INSERT INTO users (name, email) VALUES (?, ?)', ['New', 'new@x.com']));
    }

    public function testLastInsertIdReturnsPdoLastInsertId(): void {
        $this->db->exec('CREATE TABLE IF NOT EXISTS lid_test (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)');
        $this->db->exec('INSERT INTO lid_test (name) VALUES (?)', ['foo']);
        $result = $this->db->lastInsertId();

        $this->assertIsString($result);
        $this->assertSame('1', $result);
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

    public function testTransReturnsFalseOutsideTransaction(): void {
        $this->assertFalse($this->db->trans());
    }

    public function testTransReturnsTrueInsideTransaction(): void {
        $this->db->begin();
        $this->assertTrue($this->db->trans());
        $this->db->rollback();
        $this->assertFalse($this->db->trans());
    }

    public function testCountReturnsAffectedRowsAfterInsert(): void {
        $this->db->exec('INSERT INTO users (name, email) VALUES (?, ?)', ['A', 'a@x.com']);
        $this->assertSame(1, $this->db->count());

        $this->db->exec('INSERT INTO users (name, email) VALUES (?, ?), (?, ?)', ['B', 'b@x.com', 'C', 'c@x.com']);
        $this->assertSame(2, $this->db->count());
    }

    public function testCountAfterUpdate(): void {
        $this->db->exec('UPDATE users SET name = ? WHERE name = ?', ['Zed', 'Joe']);
        $this->assertSame(1, $this->db->count());
    }

    public function testCountAfterSelect(): void {
        $this->db->exec('SELECT * FROM users');
        $this->assertSame(2, $this->db->count());
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
        $db = new Db(['dsn' => 'sqlite::memory:', 'log_queries' => true]);
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

    public function testFormattedLogReturnsEmptyStringWhenNoQueries(): void {
        $db = new Db(['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $this->assertSame('', $db->log());
    }

    public function testFormattedLogReturnsExpectedFormat(): void {
        $db = new Db(['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $db->exec('SELECT 1');

        $log = $db->log();
        $this->assertIsString($log);
        $this->assertStringContainsString('SELECT 1', $log);
        $this->assertMatchesRegularExpression('/\(\d+\.\d+ms\)/', $log);
    }

    public function testResetRequestState(): void {
        $db = new Db(['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $db->exec('CREATE TABLE t (id INTEGER PRIMARY KEY)');
        $db->exec('INSERT INTO t (id) VALUES (?)', [1]);

        $this->assertSame(2, $db->queryCount());
        $this->assertSame(1, $db->count());

        $db->resetRequestState();

        $this->assertSame(0, $db->queryCount());
        $this->assertSame([], $db->queryLog());
        $this->assertSame(0.0, $db->queryTime());
        $this->assertSame(0, $db->count());
        $this->assertSame('', $db->log());
    }

    public function testBatchInsertBasic(): void {
        $this->db->batchInsert('users', ['name', 'email'], [
            ['Zed', 'zed@x.com'],
            ['Kai', 'kai@x.com'],
        ]);
        $this->assertSame(4, (int) $this->db->var('SELECT COUNT(*) FROM users'));
        $this->assertSame('Zed', $this->db->var('SELECT name FROM users WHERE email = ?', 'zed@x.com'));
    }

    public function testBatchInsertEmptyRowsIsNoop(): void {
        $this->db->batchInsert('users', ['name', 'email'], []);
        $this->assertSame(2, (int) $this->db->var('SELECT COUNT(*) FROM users'));
    }

    public function testBatchInsertEmptyColumnsIsNoop(): void {
        $this->db->batchInsert('users', [], [['Joe', 'j@x.com']]);
        $this->assertSame(2, (int) $this->db->var('SELECT COUNT(*) FROM users'));
    }

    public function testBatchInsertChunksAtSqliteLimit(): void {
        $db = new Db(['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $db->exec('CREATE TABLE bulk (a INTEGER NOT NULL, b TEXT NOT NULL, c INTEGER NOT NULL)');

        $rows = [];
        for ($i = 1; $i <= 400; $i++) {
            $rows[] = [$i, 'row-' . $i, $i * 10];
        }

        $db->batchInsert('bulk', ['a', 'b', 'c'], $rows);

        $this->assertSame(400, (int) $db->var('SELECT COUNT(*) FROM bulk'));
        $this->assertSame('row-1', $db->var('SELECT b FROM bulk WHERE a = ?', [1]));
        $this->assertSame(4000, (int) $db->var('SELECT c FROM bulk WHERE a = ?', [400]));

        $insertCount = 0;
        foreach ($db->queryLog() as $entry) {
            if (str_starts_with($entry['sql'], 'INSERT INTO bulk')) {
                $insertCount++;
            }
        }
        $this->assertSame(2, $insertCount);
    }

    public function testBatchInsertWithInsertOrIgnore(): void {
        $this->db->exec('CREATE TABLE uniq (id INTEGER PRIMARY KEY, val TEXT)');
        $this->db->exec('INSERT INTO uniq (id, val) VALUES (1, ?)', ['existing']);

        $this->db->batchInsert('uniq', ['id', 'val'], [
            [1, 'duplicate'],
            [2, 'new'],
        ], 'INSERT OR IGNORE');

        $this->assertSame(2, (int) $this->db->var('SELECT COUNT(*) FROM uniq'));
        $this->assertSame('existing', $this->db->var('SELECT val FROM uniq WHERE id = ?', [1]));
        $this->assertSame('new', $this->db->var('SELECT val FROM uniq WHERE id = ?', [2]));
    }

    public function testBatchInsertWithReplace(): void {
        $this->db->exec('CREATE TABLE rep (id INTEGER PRIMARY KEY, val TEXT)');
        $this->db->exec('INSERT INTO rep (id, val) VALUES (1, ?)', ['old']);

        $this->db->batchInsert('rep', ['id', 'val'], [
            [1, 'new'],
            [2, 'added'],
        ], 'REPLACE');

        $this->assertSame(2, (int) $this->db->var('SELECT COUNT(*) FROM rep'));
        $this->assertSame('new', $this->db->var('SELECT val FROM rep WHERE id = ?', [1]));
    }

    public function testBatchInsertWithNullValues(): void {
        $this->db->batchInsert('users', ['name', 'email'], [
            ['Nil', null],
        ]);
        $this->assertSame(3, (int) $this->db->var('SELECT COUNT(*) FROM users'));
        $this->assertNull($this->db->var('SELECT email FROM users WHERE name = ?', 'Nil'));
    }

    public function testBatchInsertSingleColumn(): void {
        $this->db->exec('CREATE TABLE tags (name TEXT NOT NULL)');

        $rows = array_map(fn($i) => ['tag-' . $i], range(1, 50));
        $this->db->batchInsert('tags', ['name'], $rows);

        $this->assertSame(50, (int) $this->db->var('SELECT COUNT(*) FROM tags'));
    }

    public function testBatchInsertRowTooLongThrows(): void {
        $this->expectException(\PDOException::class);
        $this->db->batchInsert('users', ['name', 'email'], [
            ['Joe', 'j@x.com', 'extra'],
        ]);
    }
}
