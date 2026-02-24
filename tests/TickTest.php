<?php
declare(strict_types=1);

namespace PFrame\Tests;

use PHPUnit\Framework\TestCase;
use PFrame\Tick;
use PFrame\TickTask;

class TickTest extends TestCase {
    private string $cacheDir;

    protected function setUp(): void {
        $this->cacheDir = sys_get_temp_dir() . '/pframe_tick_test_' . uniqid();
        mkdir($this->cacheDir, 0755, true);
    }

    protected function tearDown(): void {
        // cleanup cache dir
        foreach (glob($this->cacheDir . '/tick/*') ?: [] as $f) { unlink($f); }
        @rmdir($this->cacheDir . '/tick');
        @rmdir($this->cacheDir);
    }

    public function testTaskRegistration(): void {
        $tick = new Tick($this->cacheDir);
        $task = $tick->task('test_task');

        self::assertInstanceOf(TickTask::class, $task);
    }

    public function testTaskFluentApi(): void {
        $tick = new Tick($this->cacheDir);
        $called = false;

        $task = $tick->task('my_task')
            ->every(60)
            ->run(function() use (&$called) { $called = true; });

        self::assertInstanceOf(TickTask::class, $task);
    }

    public function testDispatchRunsDueTask(): void {
        $tick = new Tick($this->cacheDir);
        $counter = 0;

        $tick->task('increment')
            ->every(1)
            ->run(function() use (&$counter) { $counter++; });

        // Force: no global throttle in tests (pass forceRun: true)
        $results = $tick->dispatch(forceRun: true);

        self::assertSame(1, $counter);
        self::assertCount(1, $results);
        self::assertTrue($results['increment']['success']);
    }

    public function testDispatchSkipsNotDueTask(): void {
        $tick = new Tick($this->cacheDir);
        $counter = 0;

        $tick->task('slow')
            ->every(3600)
            ->run(function() use (&$counter) { $counter++; });

        // First run — executes
        $tick->dispatch(forceRun: true);
        self::assertSame(1, $counter);

        // Second run immediately — skipped (not due)
        $tick->dispatch(forceRun: true);
        self::assertSame(1, $counter);
    }

    public function testBetweenTimeWindow(): void {
        $tick = new Tick($this->cacheDir);
        $counter = 0;

        $tick->task('windowed')
            ->every(60)
            ->between('03:00', '05:00')
            ->run(function() use (&$counter) { $counter++; });

        // Dispatch — will only run if current time is in window
        $results = $tick->dispatch(forceRun: true);

        $hour = (int)date('G');
        if ($hour >= 3 && $hour < 5) {
            self::assertSame(1, $counter);
        } else {
            self::assertSame(0, $counter);
        }
    }

    public function testBetweenTimeWindowWithOverride(): void {
        $tick = new Tick($this->cacheDir);
        $counter = 0;

        // Window that's definitely NOT now (unless test runs at exactly this time)
        $tick->task('windowed')
            ->every(1)
            ->between('02:00', '02:01')
            ->run(function() use (&$counter) { $counter++; });

        $results = $tick->dispatch(forceRun: true);

        $hour = (int)date('G');
        $minute = (int)date('i');
        if ($hour === 2 && $minute === 0) {
            self::assertSame(1, $counter); // extremely unlikely
        } else {
            self::assertSame(0, $counter);
            self::assertEmpty($results);
        }
    }

    public function testCommandTask(): void {
        $tick = new Tick($this->cacheDir);
        $outFile = $this->cacheDir . '/cmd_output.txt';

        $tick->task('echo_test')
            ->every(1)
            ->command("echo hello > {$outFile}");

        $results = $tick->dispatch(forceRun: true);

        self::assertTrue($results['echo_test']['success']);
        self::assertStringContainsString('hello', file_get_contents($outFile));
        @unlink($outFile);
    }

    public function testCommandTimeout(): void {
        $tick = new Tick($this->cacheDir);

        $tick->task('slow_cmd')
            ->every(1)
            ->command('sleep 10', timeout: 1);

        $results = $tick->dispatch(forceRun: true);

        self::assertFalse($results['slow_cmd']['success']);
        self::assertStringContainsString('timeout', strtolower($results['slow_cmd']['error']));
    }

    public function testTaskErrorHandling(): void {
        $tick = new Tick($this->cacheDir);

        $tick->task('failing')
            ->every(1)
            ->run(function() { throw new \RuntimeException('boom'); });

        $results = $tick->dispatch(forceRun: true);

        self::assertFalse($results['failing']['success']);
        self::assertStringContainsString('boom', $results['failing']['error']);
    }

    public function testMultipleTasksExecuteInOrder(): void {
        $tick = new Tick($this->cacheDir);
        $order = [];

        $tick->task('first')
            ->every(1)
            ->run(function() use (&$order) { $order[] = 'first'; });

        $tick->task('second')
            ->every(1)
            ->run(function() use (&$order) { $order[] = 'second'; });

        $tick->dispatch(forceRun: true);

        self::assertSame(['first', 'second'], $order);
    }

    public function testGlobalThrottleSkipsWhenTooSoon(): void {
        $tick = new Tick($this->cacheDir);
        $counter = 0;

        $tick->task('throttled')
            ->every(1)
            ->run(function() use (&$counter) { $counter++; });

        // First dispatch with forceRun bypasses global throttle
        $tick->dispatch(forceRun: true);
        self::assertSame(1, $counter);

        // Without forceRun, global throttle (30s) should skip
        // We need a fresh Tick instance to not have stale state
        $tick2 = new Tick($this->cacheDir);
        $tick2->task('throttled')
            ->every(1)
            ->run(function() use (&$counter) { $counter++; });

        $tick2->dispatch(); // no forceRun — global throttle active
        // Should still be 1 because global throttle blocks re-evaluation
        self::assertSame(1, $counter);
    }
}
