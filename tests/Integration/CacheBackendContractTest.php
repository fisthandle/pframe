<?php
declare(strict_types=1);

namespace PFrame\Tests\Integration;

use PFrame\Cache;
use PHPUnit\Framework\TestCase;

class CacheBackendContractTest extends TestCase {
    public function testConfiguredCacheBackendSupportsCoreAndRateLimitContracts(): void {
        $expected = getenv('PFRAME_EXPECT_CACHE_BACKEND') ?: 'file';
        $this->assertContains($expected, ['file', 'apcu']);

        $hasApcu = function_exists('apcu_enabled') && apcu_enabled();
        $this->assertSame($expected === 'apcu', $hasApcu, 'PHP runtime selected an unexpected Cache backend.');

        $dir = sys_get_temp_dir() . '/pframe_cache_contract_' . bin2hex(random_bytes(6));
        mkdir($dir, 0777, true);

        try {
            $cache = $expected === 'apcu' ? new Cache() : new Cache($dir);
            $cache->set('contract-key', 'value', 60);
            $this->assertSame('value', $cache->get('contract-key'));
            $this->assertNull($cache->rateCheck('contract', 'subject', 1, 60));
            $this->assertIsInt($cache->rateCheck('contract', 'subject', 1, 60));
            $cache->clear();
            $this->assertSame('missing', $cache->get('contract-key', 'missing'));
        } finally {
            foreach (glob($dir . '/*') ?: [] as $file) {
                unlink($file);
            }
            foreach (glob($dir . '/.pframe-cache-lock-*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($dir);
        }
    }
}
