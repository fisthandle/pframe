<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PFrame\Cache;
use PHPUnit\Framework\TestCase;

class CacheTest extends TestCase {
    private string $dir;

    private Cache $cache;

    protected function setUp(): void {
        $this->dir = sys_get_temp_dir() . '/p1_cache_test_' . uniqid('', true);
        $this->cache = new Cache($this->dir);
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
        $this->cache->set('x', 'y');
        $file = glob($this->dir . '/*.cache')[0] ?? null;
        $this->assertNotNull($file);
        file_put_contents((string) $file, 'not serialized');

        $this->assertSame('d', $this->cache->get('x', 'd'));
    }
}
