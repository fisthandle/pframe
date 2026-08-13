<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PFrame\Performance;
use PHPUnit\Framework\TestCase;

class PerformanceTest extends TestCase {
    public function testMeasureReturnsValueAndAggregatesNormalizedSpan(): void {
        $performance = new Performance();

        $result = $performance->measure('custom.step', static fn(): string => 'ok');
        $performance->record('custom.step', 1.25);

        $snapshot = $performance->snapshot();
        $this->assertSame('ok', $result);
        $this->assertArrayHasKey('custom_step', $snapshot['spans']);
        $this->assertSame(2, $snapshot['spans']['custom_step']['count']);
        $this->assertGreaterThanOrEqual(1.25, $snapshot['spans']['custom_step']['ms']);
    }

    public function testMeasureRecordsSpanWhenCallbackThrows(): void {
        $performance = new Performance();

        try {
            $performance->measure('failed', static function (): never {
                throw new \RuntimeException('boom');
            });
            $this->fail('Expected RuntimeException');
        } catch (\RuntimeException $e) {
            $this->assertSame('boom', $e->getMessage());
        }

        $this->assertSame(1, $performance->snapshot()['spans']['failed']['count']);
    }

    public function testResetRequestStateClearsSpansAndElapsedTime(): void {
        $performance = new Performance();
        $performance->record('stale', 5.0);
        usleep(5000);
        $before = $performance->appMilliseconds();

        $performance->resetRequestState();
        $snapshot = $performance->snapshot();

        $this->assertGreaterThan(4.0, $before);
        $this->assertSame([], $snapshot['spans']);
        $this->assertLessThan($before, $snapshot['app_ms']);
    }

    public function testSnapshotContainsResourceMetrics(): void {
        $snapshot = (new Performance())->snapshot();

        $this->assertArrayHasKey('php_ms', $snapshot);
        $this->assertArrayHasKey('app_ms', $snapshot);
        $this->assertArrayHasKey('cpu_ms', $snapshot);
        $this->assertArrayHasKey('wait_ms', $snapshot);
        $this->assertArrayHasKey('mem_mb', $snapshot);
        $this->assertArrayHasKey('peak_mb', $snapshot);
        $this->assertGreaterThan(0.0, $snapshot['mem_mb']);
        $this->assertGreaterThanOrEqual($snapshot['mem_mb'], $snapshot['peak_mb']);
        if ($snapshot['cpu_ms'] === null) {
            $this->assertNull($snapshot['wait_ms']);
        } else {
            $this->assertGreaterThanOrEqual(0.0, $snapshot['cpu_ms']);
            $this->assertGreaterThanOrEqual(0.0, $snapshot['wait_ms']);
        }
    }

    public function testSnapshotIncludesCpuTimingOnNonThreadSafePhpWithGetrusage(): void {
        if (PHP_ZTS || !function_exists('getrusage')) {
            $this->markTestSkipped('CPU timing requires non-thread-safe PHP with getrusage().');
        }

        $snapshot = (new Performance())->snapshot();

        $this->assertIsFloat($snapshot['cpu_ms']);
        $this->assertIsFloat($snapshot['wait_ms']);
        $this->assertGreaterThanOrEqual(0.0, $snapshot['cpu_ms']);
        $this->assertGreaterThanOrEqual(0.0, $snapshot['wait_ms']);
    }

    public function testServerTimingUsesSafeBoundedMetricNames(): void {
        $performance = new Performance();
        $performance->record('unsafe metric/value', 1.5);
        for ($i = 0; $i < 25; $i++) {
            $performance->record('span-' . $i, 0.1);
        }

        $header = $performance->serverTiming();

        $this->assertStringContainsString('php;dur=', $header);
        $this->assertStringContainsString('app;dur=', $header);
        $this->assertStringContainsString('unsafe_metric_value;dur=1.50', $header);
        $this->assertStringNotContainsString('span-24;dur=', $header);
    }

    public function testSpanCardinalityIsBounded(): void {
        $performance = new Performance();
        for ($i = 0; $i < 100; $i++) {
            $performance->record('dynamic-' . $i, 0.1);
        }

        $spans = $performance->snapshot()['spans'];

        $this->assertCount(64, $spans);
        $this->assertSame(37, $spans['other']['count']);
    }
}
