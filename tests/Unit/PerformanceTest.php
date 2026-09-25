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

    public function testNestedMeasureLinksParentsAndSqlEventsStayCheap(): void {
        $performance = new Performance();
        $performance->setTraceEnabled(true);

        $performance->measure('outer', function () use ($performance): void {
            $performance->measure('inner', function () use ($performance): void {
                $performance->traceEvent('sql', hrtime(true), 0.5, ['sql' => 'SELECT 1']);
            });
            $performance->traceEvent('template', hrtime(true), 0.1, ['template' => 'x.php']);
        }, ['kind' => 'test']);
        $performance->traceEvent('sql', hrtime(true), 0.2);

        $events = [];
        foreach ($performance->traceEvents() as $event) {
            $events[$event['name'] . ($event['parent'] === null ? '_root' : '')] = $event;
        }
        $this->assertSame(['outer_root', 'inner', 'sql', 'template', 'sql_root'], array_keys($events));
        $this->assertNull($events['outer_root']['parent']);
        $this->assertSame($events['outer_root']['id'], $events['inner']['parent']);
        $this->assertSame($events['inner']['id'], $events['sql']['parent']);
        $this->assertSame($events['outer_root']['id'], $events['template']['parent']);
        $ids = array_column($events, 'id');
        $this->assertSame(count($ids), count(array_unique($ids)));
        $this->assertSame('test', $events['outer_root']['details']['kind']);
        foreach (['outer_root', 'inner'] as $span) {
            $this->assertArrayHasKey('cpu_ms', $events[$span]);
            $this->assertIsInt($events[$span]['mem_kb']);
        }
        foreach (['sql', 'template', 'sql_root'] as $cheap) {
            $this->assertSame(['id', 'parent', 'name', 'at_ms', 'ms', 'details'], array_keys($events[$cheap]));
        }
    }

    public function testIncompleteMeasureKeepsIdAndParent(): void {
        $performance = new Performance();
        $performance->setTraceEnabled(true);

        $performance->measure('outer', function () use ($performance): void {
            $performance->measure('inner', function () use ($performance): void {
                $performance->finishActiveTraceMeasures();
            });
        });

        $events = $performance->traceEvents();
        $this->assertSame(['outer', 'inner'], array_column($events, 'name'));
        $this->assertSame([1, 1], array_column(array_column($events, 'details'), 'incomplete'));
        $this->assertSame($events[0]['id'], $events[1]['parent']);
    }

    public function testRequestIdReusesValidIncomingHeaderAndResetsPerRequest(): void {
        $server = $_SERVER;
        try {
            $_SERVER['HTTP_X_REQUEST_ID'] = 'edge-Req_1.abc';
            $performance = new Performance();
            $this->assertSame('edge-Req_1.abc', $performance->requestId());

            foreach (['short', str_repeat('a', 65), 'bad id with spaces', "abc\ndefgh"] as $invalid) {
                $_SERVER['HTTP_X_REQUEST_ID'] = $invalid;
                $performance->resetRequestState();
                $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $performance->requestId());
            }

            unset($_SERVER['HTTP_X_REQUEST_ID']);
            $performance->resetRequestState();
            $first = $performance->requestId();
            $this->assertSame($first, $performance->requestId());
            $performance->resetRequestState();
            $this->assertNotSame($first, $performance->requestId());
        } finally {
            $_SERVER = $server;
        }
    }

    public function testSnapshotContainsChildrenCpu(): void {
        $snapshot = (new Performance())->snapshot();

        $this->assertArrayHasKey('children_cpu_ms', $snapshot);
        if (PHP_ZTS || !function_exists('getrusage')) {
            $this->assertNull($snapshot['children_cpu_ms']);
        } else {
            $this->assertIsFloat($snapshot['children_cpu_ms']);
            $this->assertGreaterThanOrEqual(0.0, $snapshot['children_cpu_ms']);
        }
    }

    public function testMeasureProcessRecordsExitCodeAndChildrenCpu(): void {
        $performance = new Performance();
        $performance->setTraceEnabled(true);

        $exitCode = $performance->measureProcess('php', static function (): int {
            $process = proc_open([PHP_BINARY, '-r', 'for ($i = 0; $i < 300000; $i++) { md5((string) $i); } exit(3);'], [], $pipes);
            return is_resource($process) ? proc_close($process) : -1;
        });
        $result = $performance->measureProcess('array', static fn(): array => ['exit_code' => 0, 'stdout' => 'ok']);
        $performance->measureProcess('none', static fn(): string => 'text');

        $this->assertSame(3, $exitCode);
        $this->assertSame(['exit_code' => 0, 'stdout' => 'ok'], $result);
        $events = $performance->traceEvents();
        $this->assertSame(['process_exec', 'process_exec', 'process_exec'], array_column($events, 'name'));
        $details = array_column($events, 'details');
        $this->assertSame(['php', 'array', 'none'], array_column($details, 'program'));
        $this->assertSame([3, 0, null], array_column($details, 'exit_code'));
        if (!PHP_ZTS && function_exists('getrusage')) {
            $this->assertGreaterThan(0.0, $details[0]['children_cpu_ms']);
        }
        $this->assertSame(3, $performance->snapshot()['spans']['process_exec']['count']);
    }

    public function testMeasureHttpRecordsCurlTimings(): void {
        if (!function_exists('curl_init')) {
            $this->markTestSkipped('Requires ext-curl.');
        }
        $file = tempnam(sys_get_temp_dir(), 'pframe_http_');
        file_put_contents($file, str_repeat('x', 1234));
        try {
            $performance = new Performance();
            $performance->setTraceEnabled(true);
            $ok = curl_init('file://' . $file);
            curl_setopt($ok, CURLOPT_RETURNTRANSFER, true);
            $missing = curl_init('file://' . $file . '.missing');
            curl_setopt($missing, CURLOPT_RETURNTRANSFER, true);

            $performance->measure('outer', function () use ($performance, $ok, $missing): void {
                $this->assertSame(str_repeat('x', 1234), $performance->measureHttp('local', $ok));
                $this->assertFalse($performance->measureHttp('missing', $missing));
            });

            $events = array_values(array_filter($performance->traceEvents(), static fn(array $event): bool => $event['name'] === 'http_request'));
            $this->assertCount(2, $events);
            $outer = array_values(array_filter($performance->traceEvents(), static fn(array $event): bool => $event['name'] === 'outer'))[0];
            $this->assertSame($outer['id'], $events[0]['parent']);
            $this->assertArrayHasKey('cpu_ms', $events[0]);
            $details = $events[0]['details'];
            $this->assertSame('local', $details['service']);
            $this->assertIsInt($details['http_status']);
            $this->assertSame(1234, $details['bytes']);
            $this->assertSame(0, $details['curl_errno']);
            foreach (['total_ms', 'dns_ms', 'connect_ms', 'tls_ms', 'ttfb_ms'] as $key) {
                $this->assertIsNumeric($details[$key], $key);
                $this->assertGreaterThanOrEqual(0, $details[$key], $key);
            }
            $this->assertSame('missing', $events[1]['details']['service']);
            $this->assertGreaterThan(0, $events[1]['details']['curl_errno']);
            $this->assertSame(2, $performance->snapshot()['spans']['http_request']['count']);
        } finally {
            @unlink($file);
        }
    }

    public function testMeasureHttpWithoutTraceIsPlainCurlExec(): void {
        if (!function_exists('curl_init')) {
            $this->markTestSkipped('Requires ext-curl.');
        }
        $file = tempnam(sys_get_temp_dir(), 'pframe_http_');
        file_put_contents($file, 'plain');
        try {
            $performance = new Performance();
            $ch = curl_init('file://' . $file);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

            $this->assertSame('plain', $performance->measureHttp('local', $ch));
            $this->assertSame([], $performance->traceEvents());
            $this->assertSame([], $performance->snapshot()['spans']);
        } finally {
            @unlink($file);
        }
    }

    public function testTraceEventsAreCappedAndDroppedEventsCounted(): void {
        $performance = new Performance();
        $performance->setTraceEnabled(true);
        for ($i = 0; $i < 5003; $i++) {
            $performance->traceEvent('sql', hrtime(true), 0.1);
        }

        $this->assertCount(5000, $performance->traceEvents());
        $this->assertSame(3, $performance->droppedTraceEvents());

        $performance->resetRequestState();
        $this->assertSame(0, $performance->droppedTraceEvents());
    }
}
