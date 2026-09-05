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

    public function testIncrementKeepsOriginalTtlForExistingEntry(): void {
        $expected = getenv('PFRAME_EXPECT_CACHE_BACKEND') ?: 'file';
        $dir = sys_get_temp_dir() . '/pframe_cache_ttl_contract_' . bin2hex(random_bytes(6));
        mkdir($dir, 0777, true);
        $cache = null;

        try {
            $cache = $expected === 'apcu' ? new Cache() : new Cache($dir);
            $key = 'ttl-contract-' . bin2hex(random_bytes(6));
            $permanentKey = $key . '-permanent';
            $cache->set($key, 1, 2);
            $cache->set($permanentKey, 7);

            $this->assertSame(2, $cache->increment($key, 60));
            $this->assertSame(8, $cache->increment($permanentKey, 1));
            sleep(3);
            $this->assertSame('expired', $cache->get($key, 'expired'));
            $this->assertSame(8, $cache->get($permanentKey));
            $this->assertSame(1, $cache->increment($key, 60));
        } finally {
            $cache?->clear();
            foreach (glob($dir . '/*') ?: [] as $file) {
                unlink($file);
            }
            foreach (glob($dir . '/.pframe-cache-lock-*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($dir);
        }
    }

    public function testApcuClearRemovesOwnEntriesAndKeepsForeignKeys(): void {
        if (!function_exists('apcu_enabled') || !apcu_enabled()) {
            $this->markTestSkipped('APCu is disabled in this environment.');
        }

        $dir = sys_get_temp_dir() . '/pframe_cache_apcu_contract_' . bin2hex(random_bytes(6));
        mkdir($dir, 0777, true);
        $cache = new Cache($dir);
        $ownKey = 'own-' . bin2hex(random_bytes(6));
        $foreignKey = 'foreign-' . bin2hex(random_bytes(6));
        apcu_store($foreignKey, 'keep');

        try {
            for ($i = 0; $i < 257; $i++) {
                $cache->set($ownKey . $i, 'remove');
            }
            $cache->clear();

            for ($i = 0; $i < 257; $i++) {
                $this->assertSame('missing', $cache->get($ownKey . $i, 'missing'));
            }
            $this->assertSame('keep', apcu_fetch($foreignKey));
        } finally {
            apcu_delete($foreignKey);
            $cache->clear();
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
