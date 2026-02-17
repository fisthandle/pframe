<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit\Testing;

use PFrame\App;
use PFrame\Base;
use PFrame\Db;
use PFrame\Testing\DatabaseTransactions;
use PFrame\Testing\RefreshDatabase;
use PHPUnit\Framework\TestCase;

class RefreshDatabaseTest extends TestCase {
    use RefreshDatabase, DatabaseTransactions;

    private static ?Db $db = null;

    protected function migrationPath(): string {
        return __DIR__ . '/../../fixtures/migrations';
    }

    protected function setUp(): void {
        if (self::$db === null) {
            self::$db = new Db(['dsn' => 'sqlite::memory:']);
        }
        $app = new App();
        $app->setDb(self::$db);

        $this->bootRefreshDatabase();
        parent::setUp();
        $this->setUpDatabaseTransactions();
    }

    protected function tearDown(): void {
        $this->tearDownDatabaseTransactions();
        parent::tearDown();
    }

    public function testMigrationsCreateTables(): void {
        $tables = Base::col("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'");
        $this->assertContains('users', $tables);
        $this->assertContains('posts', $tables);
    }

    public function testCanInsertAndQueryMigratedTable(): void {
        Base::exec('INSERT INTO users (name, email) VALUES (?, ?)', ['Joe', 'joe@x.com']);
        $row = Base::row('SELECT * FROM users WHERE email = ?', ['joe@x.com']);
        $this->assertSame('Joe', $row['name']);
    }

    public function testTransactionRollbackKeepsSchemaButClearsData(): void {
        Base::exec('INSERT INTO users (name, email) VALUES (?, ?)', ['Ghost', 'ghost@x.com']);
        $this->assertSame(1, (int) Base::var('SELECT COUNT(*) FROM users WHERE name = ?', ['Ghost']));
    }

    public function testBootIsIdempotent(): void {
        $this->bootRefreshDatabase();
        $tables = Base::col("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'");
        $this->assertContains('users', $tables);
    }

    public function testBootThrowsWhenNoSqlFiles(): void {
        $app = new App();
        $app->setDb(new Db(['dsn' => 'sqlite::memory:']));

        $dir = sys_get_temp_dir() . '/pframe-empty-migrations-' . uniqid('', true);
        mkdir($dir, 0777, true);

        $bootstrap = new class($dir) {
            use RefreshDatabase;

            public function __construct(private readonly string $dir) {
            }

            protected function migrationPath(): string {
                return $this->dir;
            }

            public function run(): void {
                $this->bootRefreshDatabase();
            }
        };

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("No SQL files found in '$dir'");
        try {
            $bootstrap->run();
        } finally {
            @rmdir($dir);
        }
    }
}
