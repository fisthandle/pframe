<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PFrame\App;
use PFrame\Db;
use PFrame\DebugBar;
use PHPUnit\Framework\TestCase;

class DebugBarTest extends TestCase {
    public function testToArrayWithoutDb(): void {
        $app = new App();
        $bar = new DebugBar($app);
        $data = $bar->toArray();

        $this->assertArrayHasKey('gen_ms', $data);
        $this->assertArrayHasKey('db_ms', $data);
        $this->assertArrayHasKey('db_count', $data);
        $this->assertArrayHasKey('mem_mb', $data);
        $this->assertArrayHasKey('peak_mb', $data);
        $this->assertArrayHasKey('queries', $data);
        $this->assertArrayHasKey('duplicates', $data);
        $this->assertArrayHasKey('slowest', $data);
        $this->assertArrayHasKey('included_files', $data);
        $this->assertSame(0.0, $data['db_ms']);
        $this->assertSame(0, $data['db_count']);
        $this->assertSame([], $data['queries']);
        $this->assertSame([], $data['duplicates']);
        $this->assertSame([], $data['slowest']);
        $this->assertIsArray($data['included_files']);
        $this->assertGreaterThan(0, count($data['included_files']));
        $this->assertGreaterThanOrEqual(0, $data['gen_ms']);
        $this->assertGreaterThan(0, $data['mem_mb']);
    }

    public function testToArrayDoesNotInitializeDb(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:', 'log_queries' => true]);

        $bar = new DebugBar($app);
        $data = $bar->toArray();

        $this->assertNull($app->dbIfInitialized(), 'toArray() should not force DB initialization');
        $this->assertSame([], $data['queries']);
    }

    public function testToArrayWithQueries(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $app->db()->exec('CREATE TABLE t (id INTEGER PRIMARY KEY)');
        $app->db()->exec('INSERT INTO t (id) VALUES (?)', [1]);
        $app->db()->var('SELECT COUNT(*) FROM t');

        $bar = new DebugBar($app);
        $data = $bar->toArray();

        $this->assertSame(3, $data['db_count']);
        $this->assertGreaterThan(0, $data['db_ms']);
        $this->assertCount(3, $data['queries']);
        $this->assertStringContainsString('CREATE TABLE', $data['queries'][0]['sql']);
        $this->assertGreaterThanOrEqual(0, $data['queries'][0]['ms']);
    }

    public function testToJson(): void {
        $app = new App();
        $bar = new DebugBar($app);
        $json = $bar->toJson();

        $decoded = json_decode($json, true);
        $this->assertIsArray($decoded);
        $this->assertArrayHasKey('gen_ms', $decoded);
        $this->assertArrayHasKey('queries', $decoded);
    }

    public function testRenderContainsHtml(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $app->db()->exec('CREATE TABLE t (id INTEGER PRIMARY KEY)');
        $app->db()->var('SELECT COUNT(*) FROM t');

        $bar = new DebugBar($app);
        $html = $bar->render();

        $this->assertStringContainsString('Gen:', $html);
        $this->assertStringContainsString('DB:', $html);
        $this->assertStringContainsString('Mem:', $html);
        $this->assertStringContainsString('toggle', $html);
        $this->assertStringContainsString('<script>', $html);
        $this->assertStringContainsString('CREATE TABLE', $html);
        $this->assertStringContainsString('(2)', $html);
    }

    public function testRenderNoQueries(): void {
        $app = new App();
        $bar = new DebugBar($app);
        $html = $bar->render();

        $this->assertStringContainsString('Brak zapytań.', $html);
        $this->assertStringContainsString('(0)', $html);
    }

    public function testRenderTruncatesLongSql(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $app->db()->exec('CREATE TABLE t (col1 TEXT, col2 TEXT, col3 TEXT, col4 TEXT, col5 TEXT, col6 TEXT, col7 TEXT, col8 TEXT, col9 TEXT, col10 TEXT, col11 TEXT, col12 TEXT)');

        $bar = new DebugBar($app);
        $html = $bar->render();

        // Short version should have ellipsis
        $this->assertStringContainsString('…', $html);
        // Full version should have full SQL
        $this->assertStringContainsString('col12', $html);
    }

    public function testRenderEscapesHtml(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $app->db()->exec("CREATE TABLE t (name TEXT DEFAULT '<script>')");

        $bar = new DebugBar($app);
        $html = $bar->render();

        // h() should escape the <script> in SQL
        $this->assertStringContainsString('&lt;script&gt;', $html);
        $this->assertStringNotContainsString("DEFAULT '<script>'", $html);
    }

    public function testDuplicateDetection(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $app->db()->exec('CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)');
        $app->db()->exec('INSERT INTO t (id, name) VALUES (?, ?)', [1, 'a']);
        $app->db()->exec('INSERT INTO t (id, name) VALUES (?, ?)', [2, 'b']);
        $app->db()->exec('INSERT INTO t (id, name) VALUES (?, ?)', [3, 'c']);
        $app->db()->var('SELECT name FROM t WHERE id = ?', [1]);
        $app->db()->var('SELECT name FROM t WHERE id = ?', [2]);

        $bar = new DebugBar($app);
        $data = $bar->toArray();

        // INSERT repeated 3x, SELECT repeated 2x
        $this->assertCount(2, $data['duplicates']);
        $this->assertSame(3, $data['duplicates'][0]['count']);
        $this->assertSame(2, $data['duplicates'][1]['count']);
    }

    public function testSlowestTop3(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $app->db()->exec('CREATE TABLE t (id INTEGER PRIMARY KEY)');
        for ($i = 1; $i <= 5; $i++) {
            $app->db()->exec('INSERT INTO t (id) VALUES (?)', [$i]);
        }

        $bar = new DebugBar($app);
        $data = $bar->toArray();

        // 6 queries total, but slowest capped at 3
        $this->assertCount(3, $data['slowest']);
        // Sorted descending by ms
        $this->assertGreaterThanOrEqual($data['slowest'][1]['ms'], $data['slowest'][0]['ms']);
        $this->assertGreaterThanOrEqual($data['slowest'][2]['ms'], $data['slowest'][1]['ms']);
    }

    public function testRenderShowsInsights(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $app->db()->exec('CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)');
        $app->db()->var('SELECT name FROM t WHERE id = ?', [1]);
        $app->db()->var('SELECT name FROM t WHERE id = ?', [2]);

        $bar = new DebugBar($app);
        $html = $bar->render();

        $this->assertStringNotContainsString('Top slow:', $html);
        $this->assertStringContainsString('N+1 candidates:', $html);
        $this->assertStringContainsString('2×', $html);
        $this->assertStringContainsString('-dups-short', $html);
        $this->assertStringContainsString('-dups-full', $html);
        $this->assertStringContainsString("['queries','slow','dups']", $html);
        $this->assertStringContainsString('Files:', $html);
    }

    public function testRenderHidesInsightsWhenNoDuplicates(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $app->db()->exec('CREATE TABLE t (id INTEGER PRIMARY KEY)');

        $bar = new DebugBar($app);
        $html = $bar->render();

        $this->assertStringNotContainsString('Top slow:', $html);
        $this->assertStringNotContainsString('N+1 candidates:', $html);
        $this->assertStringNotContainsString('-insights', $html);
    }

    public function testRenderShowsTopSlowWhenDbCountAtLeastTen(): void {
        $app = new App();
        $app->setConfig('db', ['dsn' => 'sqlite::memory:', 'log_queries' => true]);
        $app->db()->exec('CREATE TABLE t (id INTEGER PRIMARY KEY)');
        for ($i = 1; $i <= 9; $i++) {
            $app->db()->exec('INSERT INTO t (id) VALUES (?)', [$i]);
        }

        $bar = new DebugBar($app);
        $html = $bar->render();

        $this->assertStringContainsString('Top slow:', $html);
    }
}
