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

    public function testExpiresData(): void {
        $file = $this->dir . '/' . md5('ttl') . '.cache';
        file_put_contents($file, serialize(['value' => 'v', 'ttl' => 1, 'time' => time() - 5]));
        $this->assertSame('fallback', $this->cache->get('ttl', 'fallback'));
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
    }

    public function testClearRemovesRateLimitLockFiles(): void {
        $this->cache->rateCheck('login', '1.2.3.4', 1, 60);
        $locksBefore = glob($this->dir . '/*.lock') ?: [];
        $this->assertNotEmpty($locksBefore);

        $this->cache->clear();

        $locksAfter = glob($this->dir . '/*.lock') ?: [];
        $this->assertSame([], $locksAfter);
    }
}
