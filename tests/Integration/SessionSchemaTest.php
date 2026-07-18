<?php
declare(strict_types=1);

namespace PFrame\Tests\Integration;

use PFrame\Db;
use PFrame\Session;
use PHPUnit\Framework\TestCase;

class SessionSchemaTest extends TestCase {
    public function testDistributedSqliteSchemaSupportsSessionLifecycle(): void {
        $pdo = new \PDO('sqlite::memory:');
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        $pdo->exec($this->schema('sessions.sqlite.sql'));

        $columns = $pdo->query("PRAGMA table_info('sessions')")->fetchAll(\PDO::FETCH_COLUMN, 1);
        $indexes = $pdo->query("PRAGMA index_list('sessions')")->fetchAll(\PDO::FETCH_COLUMN, 1);
        $this->assertSame(['session_id', 'data', 'ip', 'agent', 'stamp'], $columns);
        $this->assertContains('idx_sessions_stamp', $indexes);

        $db = new Db(['dsn' => 'sqlite::memory:']);
        $db->pdo()->exec($this->schema('sessions.sqlite.sql'));
        $this->assertSessionLifecycle($db, advisory: true);
    }

    public function testDistributedMysqlSchemaSupportsAdvisorySessionLifecycle(): void {
        $dsn = getenv('PFRAME_MYSQL_DSN');
        if (!is_string($dsn) || $dsn === '') {
            if (getenv('PFRAME_REQUIRE_MYSQL') === '1') {
                $this->fail('PFRAME_MYSQL_DSN is required by this test environment.');
            }
            $this->markTestSkipped('MySQL contract requires PFRAME_MYSQL_DSN.');
        }

        $config = [
            'dsn' => $dsn,
            'user' => getenv('PFRAME_MYSQL_USER') ?: null,
            'pass' => getenv('PFRAME_MYSQL_PASS') ?: null,
        ];
        $db = new Db($config);
        $pdo = $db->pdo();
        $pdo->exec('DROP TABLE IF EXISTS sessions');

        try {
            $pdo->exec($this->schema('sessions.sql'));
            $columns = $pdo->query('SHOW COLUMNS FROM sessions')->fetchAll(\PDO::FETCH_COLUMN);
            $indexes = $pdo->query('SHOW INDEX FROM sessions')->fetchAll(\PDO::FETCH_ASSOC);

            $this->assertSame(['session_id', 'data', 'ip', 'agent', 'stamp'], $columns);
            $this->assertContains('idx_stamp', array_column($indexes, 'Key_name'));
            $this->assertSessionLifecycle($db, advisory: true);
        } finally {
            $pdo->exec('DROP TABLE IF EXISTS sessions');
        }
    }

    private function assertSessionLifecycle(Db $db, bool $advisory): void {
        $id = 'schema-contract-' . bin2hex(random_bytes(8));
        $writer = new Session($db, advisory: $advisory, lockTimeout: 1);
        $writer->open('', '');
        $this->assertSame('', $writer->read($id));
        $this->assertTrue($writer->write($id, 'payload'));

        $reader = new Session($db, advisory: $advisory, lockTimeout: 1);
        $reader->open('', '');
        $this->assertSame('payload', $reader->read($id));
        $this->assertTrue($reader->close());

        $db->exec('UPDATE sessions SET stamp = 1 WHERE session_id = ?', [$id]);
        $collector = new Session($db, advisory: false);
        $this->assertSame(1, $collector->gc(0));
        $this->assertNull($db->var('SELECT data FROM sessions WHERE session_id = ?', [$id]));
    }

    private function schema(string $filename): string {
        $path = dirname(__DIR__, 2) . '/db/' . $filename;
        $schema = file_get_contents($path);
        $this->assertNotFalse($schema, 'Cannot read distributed schema: ' . $path);
        return (string) $schema;
    }
}
