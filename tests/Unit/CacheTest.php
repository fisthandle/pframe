<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PFrame\Cache;
use PHPUnit\Framework\TestCase;

class CacheTest extends TestCase {
    private string $dir;

    private Cache $cache;
    private bool $hasApcu;

    protected function setUp(): void {
        $this->dir = sys_get_temp_dir() . '/p1_cache_test_' . uniqid('', true);
        mkdir($this->dir, 0755, true);
        $this->cache = new Cache($this->dir);
        $this->hasApcu = function_exists('apcu_enabled') && apcu_enabled();
    }

    protected function tearDown(): void {
        $this->cache->clear();
        if (is_dir($this->dir)) {
            foreach (glob($this->dir . '/.pframe-cache-lock-*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($this->dir);
        }
    }

    public function testSetAndGet(): void {
        $this->cache->set('key', 'value');
        $this->assertSame('value', $this->cache->get('key'));
    }

    public function testDefault(): void {
        $this->assertSame('fallback', $this->cache->get('nope', 'fallback'));
    }

    public function testConstructorWithoutDirThrowsWhenApcuUnavailable(): void {
        if ($this->hasApcu) {
            $this->markTestSkipped('APCu is enabled in this environment.');
        }

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Cache directory is required when APCu is unavailable.');
        new Cache();
    }

    public function testApcuModeWorksWithoutDir(): void {
        if (!$this->hasApcu) {
            $this->markTestSkipped('APCu is disabled in this environment.');
        }

        $cache = new Cache();
        $cache->set('no-dir-key', 'value', 60);
        $this->assertSame('value', $cache->get('no-dir-key'));
        $this->assertNull($cache->rateCheck('login', '9.8.7.6', 1, 60));
        $retry = $cache->rateCheck('login', '9.8.7.6', 1, 60);
        $this->assertIsInt($retry);

        $cache->clear();
        $this->assertSame('fallback', $cache->get('no-dir-key', 'fallback'));
    }

    public function testDelete(): void {
        $this->cache->set('k', 'v');
        $this->cache->delete('k');
        $this->assertNull($this->cache->get('k'));
    }

    public function testRateCheck(): void {
        $this->assertNull($this->cache->rateCheck('login', '1.2.3.4', 3, 60));
        $this->assertNull($this->cache->rateCheck('login', '1.2.3.4', 3, 60));
        $this->assertNull($this->cache->rateCheck('login', '1.2.3.4', 3, 60));
        $retry = $this->cache->rateCheck('login', '1.2.3.4', 3, 60);
        $this->assertIsInt($retry);
        $this->assertGreaterThan(0, $retry);
    }

    public function testRateCheckResetsInvalidState(): void {
        $key = 'rl:login:invalid-state';
        $this->cache->set($key, ['count' => 'invalid', 'start' => []], 60);

        $this->assertNull($this->cache->rateCheck('login', 'invalid-state', 3, 60));
        $state = $this->cache->get($key);
        $this->assertIsArray($state);
        $this->assertSame(1, $state['count']);
        $this->assertIsInt($state['start']);
    }

    public function testIncrementStartsAtOneAndIncrementsAtomically(): void {
        $key = 'increment-' . bin2hex(random_bytes(6));

        $this->assertSame(1, $this->cache->increment($key, 60));
        $this->assertSame(2, $this->cache->increment($key, 60));
        $this->assertSame(2, $this->cache->get($key));
    }

    public function testIncrementTreatsExpiredFileAsZero(): void {
        if ($this->hasApcu) {
            $this->markTestSkipped('This regression exercises the file backend.');
        }

        $key = 'expired-increment-' . bin2hex(random_bytes(6));
        file_put_contents(
            $this->dir . '/' . md5($key) . '.cache',
            serialize(['value' => 17, 'ttl' => 1, 'time' => time() - 5]),
        );

        $this->assertSame(1, $this->cache->increment($key, 60));
        $this->assertSame(1, $this->cache->get($key));
    }

    public function testIncrementRejectsNonIntegerFileState(): void {
        if ($this->hasApcu) {
            $this->markTestSkipped('This regression exercises the file backend.');
        }

        $key = 'invalid-increment-' . bin2hex(random_bytes(6));
        file_put_contents(
            $this->dir . '/' . md5($key) . '.cache',
            serialize(['value' => 'not-an-integer', 'ttl' => 60, 'time' => time()]),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Cache entry is not an integer');
        $this->cache->increment($key);
    }

    public function testRateCheckFailsClosedWhenLockCannotBeCreated(): void {
        $readOnlyDir = sys_get_temp_dir() . '/p1_cache_test_ro_' . uniqid('', true);
        mkdir($readOnlyDir, 0755, true);
        chmod($readOnlyDir, 0555);

        try {
            $cache = new Cache($readOnlyDir);
            $retry = $cache->rateCheck('login', '1.2.3.4', 3, 60);

            $this->assertSame(1, $retry);
            $this->assertSame([], glob($readOnlyDir . '/*.cache') ?: []);
        } finally {
            chmod($readOnlyDir, 0755);
            foreach (glob($readOnlyDir . '/*') ?: [] as $file) {
                unlink($file);
            }
            if (is_dir($readOnlyDir)) {
                rmdir($readOnlyDir);
            }
        }
    }

    public function testRateCheckFailsClosedWhenStateCannotBePersisted(): void {
        if ($this->hasApcu) {
            $this->markTestSkipped('This regression exercises the file backend.');
        }

        $dir = sys_get_temp_dir() . '/p1_cache_test_persist_' . uniqid('', true);
        mkdir($dir, 0755, true);
        $lockFile = $dir . '/' . md5('rl:login:state-failure') . '.lock';
        touch($lockFile);
        chmod($lockFile, 0666);
        $cache = new Cache($dir);
        chmod($dir, 0555);

        try {
            $this->assertSame(1, $cache->rateCheck('login', 'state-failure', 3, 60));
            $this->assertSame([], glob($dir . '/*.cache') ?: []);
        } finally {
            chmod($dir, 0755);
            unlink($lockFile);
            rmdir($dir);
        }
    }

    public function testExpiresData(): void {
        $file = $this->dir . '/' . md5('ttl') . '.cache';
        file_put_contents($file, serialize(['value' => 'v', 'ttl' => 1, 'time' => time() - 5]));
        $this->assertSame('fallback', $this->cache->get('ttl', 'fallback'));
    }

    public function testPruneExpiredRemovesExpiredEntriesOnly(): void {
        if ($this->hasApcu) {
            $this->markTestSkipped('This regression exercises the file backend.');
        }

        $this->cache->set('fresh', 'keep', 3600);
        $expired = $this->dir . '/' . md5('expired') . '.cache';
        file_put_contents($expired, serialize(['value' => 'drop', 'ttl' => 1, 'time' => time() - 5]));

        $this->assertSame(1, $this->cache->pruneExpired());
        $this->assertFileDoesNotExist($expired);
        $this->assertSame('keep', $this->cache->get('fresh'));
    }

    public function testPruneExpiredHonorsRemovalLimit(): void {
        if ($this->hasApcu) {
            $this->markTestSkipped('This regression exercises the file backend.');
        }

        foreach (range(1, 3) as $i) {
            file_put_contents(
                $this->dir . '/' . md5('expired-' . $i) . '.cache',
                serialize(['value' => $i, 'ttl' => 1, 'time' => time() - 5]),
            );
        }

        $this->assertSame(2, $this->cache->pruneExpired(2));
        $this->assertCount(1, glob($this->dir . '/*.cache') ?: []);
    }

    public function testClear(): void {
        $this->cache->set('a', 1);
        $this->cache->set('b', 2);
        $this->cache->clear();
        $this->assertSame('x', $this->cache->get('a', 'x'));
        $this->assertSame('y', $this->cache->get('b', 'y'));
    }

    public function testCorruptedCacheFileFallsBack(): void {
        if ($this->hasApcu) {
            $file = $this->dir . '/' . md5('x') . '.cache';
            file_put_contents($file, 'not serialized');

            $this->cache->set('x', 'y');
            $this->assertSame('y', $this->cache->get('x', 'd'));
            return;
        }

        $this->cache->set('x', 'y');
        $file = glob($this->dir . '/*.cache')[0] ?? null;
        $this->assertNotNull($file);
        file_put_contents((string) $file, 'not serialized');

        $this->assertSame('d', $this->cache->get('x', 'd'));
        $this->assertFileExists((string) $file, 'Reader must not unlink a file that may be replaced concurrently');
    }

    public function testClearKeepsStableLockFiles(): void {
        if ($this->hasApcu) {
            $this->markTestSkipped('This regression exercises the file backend.');
        }

        $this->cache->rateCheck('login', '1.2.3.4', 1, 60);
        $locksBefore = glob($this->dir . '/.pframe-cache-lock-*') ?: [];
        $this->assertNotEmpty($locksBefore);

        $this->cache->clear();

        $locksAfter = glob($this->dir . '/.pframe-cache-lock-*') ?: [];
        $this->assertSame($locksBefore, $locksAfter);
    }

    public function testFileLocksUseBoundedStriping(): void {
        if ($this->hasApcu) {
            $this->markTestSkipped('This regression exercises the file backend.');
        }

        $pathMethod = new \ReflectionMethod($this->cache, 'fileLockPath');
        $paths = [];
        for ($i = 0; $i < 8192; $i++) {
            $path = (string) $pathMethod->invoke($this->cache, md5('key-' . $i));
            $paths[basename($path)] = true;
        }

        $this->assertLessThanOrEqual(4096, count($paths));
        $invalid = array_filter(
            array_keys($paths),
            static fn(string $filename): bool => preg_match('/^\.pframe-cache-lock-[0-9a-f]{3}$/', $filename) !== 1,
        );
        $this->assertSame([], array_values($invalid));
    }
}
