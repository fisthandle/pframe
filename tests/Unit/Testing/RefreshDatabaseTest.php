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

    private function useDatabase(Db $db): void {
        $app = new App();
        $app->setDb($db);
    }

    private function restoreTestDatabase(): void {
        if (self::$db === null) {
            throw new \LogicException('Test database is not initialized.');
        }
        $this->useDatabase(self::$db);
        $this->setUpDatabaseTransactions();
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

    public function testTransactionRollbackPreservesSchemaAndClearsData(): void {
        Base::exec('INSERT INTO users (name, email) VALUES (?, ?)', ['Ghost', 'ghost@x.com']);
        $this->assertSame(1, (int) Base::var('SELECT COUNT(*) FROM users WHERE name = ?', ['Ghost']));

        $this->tearDownDatabaseTransactions();

        $tables = Base::col("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'");
        $this->assertContains('users', $tables);
        $this->assertSame(0, (int) Base::var('SELECT COUNT(*) FROM users WHERE name = ?', ['Ghost']));

        $this->setUpDatabaseTransactions();
    }

    public function testBootIsIdempotent(): void {
        $this->bootRefreshDatabase();
        $tables = Base::col("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'");
        $this->assertContains('users', $tables);
    }

    public function testBootThrowsWhenNoSqlFiles(): void {
        $this->tearDownDatabaseTransactions();
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
            $this->restoreTestDatabase();
        }
    }

    public function testMigrationsRunForEachPdoInstance(): void {
        $path = __DIR__ . '/../../fixtures/migrations';
        $this->tearDownDatabaseTransactions();

        try {
            $firstDb = new Db(['dsn' => 'sqlite::memory:']);
            $this->useDatabase($firstDb);
            (new RefreshDatabaseHarness($path))->boot();
            $this->assertContains('users', $firstDb->col("SELECT name FROM sqlite_master WHERE type='table'"));

            $secondDb = new Db(['dsn' => 'sqlite::memory:']);
            $this->useDatabase($secondDb);
            (new RefreshDatabaseHarness($path))->boot();
            $this->assertContains('users', $secondDb->col("SELECT name FROM sqlite_master WHERE type='table'"));
        } finally {
            $this->restoreTestDatabase();
        }
    }

    public function testMigrationsRunForEachPathOnSamePdo(): void {
        $root = sys_get_temp_dir() . '/pframe-migration-paths-' . bin2hex(random_bytes(6));
        $firstPath = $root . '/first';
        $secondPath = $root . '/second';
        mkdir($firstPath, 0777, true);
        mkdir($secondPath, 0777, true);
        file_put_contents($firstPath . '/001-first.sql', 'CREATE TABLE first_path_table (id INTEGER PRIMARY KEY);');
        file_put_contents($secondPath . '/001-second.sql', 'CREATE TABLE second_path_table (id INTEGER PRIMARY KEY);');
        $this->tearDownDatabaseTransactions();

        try {
            $db = new Db(['dsn' => 'sqlite::memory:']);
            $this->useDatabase($db);

            (new RefreshDatabaseHarness($firstPath))->boot();
            (new RefreshDatabaseHarness($secondPath))->boot();

            $tables = $db->col("SELECT name FROM sqlite_master WHERE type='table'");
            $this->assertContains('first_path_table', $tables);
            $this->assertContains('second_path_table', $tables);
        } finally {
            @unlink($firstPath . '/001-first.sql');
            @unlink($secondPath . '/001-second.sql');
            @rmdir($firstPath);
            @rmdir($secondPath);
            @rmdir($root);
            $this->restoreTestDatabase();
        }
    }
}

class RefreshDatabaseHarness {
    use RefreshDatabase;

    public function __construct(private readonly string $path) {
    }

    protected function migrationPath(): string {
        return $this->path;
    }

    public function boot(): void {
        $this->bootRefreshDatabase();
    }
}
