<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PHPUnit\Framework\TestCase;
use PFrame\Log;
use PFrame\Tick;
use PFrame\TickTask;

class TickTest extends TestCase {
    private string $cacheDir;
    /** @var list<string> */
    private array $cacheDirs = [];

    protected function setUp(): void {
        $this->cacheDir = $this->createCacheDir('pframe_tick_test_');
    }

    protected function tearDown(): void {
        foreach ($this->cacheDirs as $cacheDir) {
            foreach (glob($cacheDir . '/tick/*') ?: [] as $file) {
                @unlink($file);
            }
            @rmdir($cacheDir . '/tick');
            foreach (glob($cacheDir . '/*') ?: [] as $file) {
                @unlink($file);
            }
            @rmdir($cacheDir);
        }
    }

    private function createCacheDir(string $prefix): string {
        $dir = sys_get_temp_dir() . '/' . $prefix . uniqid('', true);
        mkdir($dir, 0755, true);
        $this->cacheDirs[] = $dir;
        return $dir;
    }

    private function lockPath(string $cacheDir, string $taskName, string $prefix = ''): string {
        $keyPrefix = 'tick:' . ($prefix !== '' ? $prefix : md5($cacheDir)) . ':';
        return $cacheDir . '/tick/' . md5($keyPrefix . $taskName . ':lock') . '.lock';
    }

    private function failPath(string $cacheDir, string $taskName, string $prefix = ''): string {
        $keyPrefix = 'tick:' . ($prefix !== '' ? $prefix : md5($cacheDir)) . ':';
        return $cacheDir . '/tick/' . md5($keyPrefix . $taskName . ':fail') . '.fail';
    }

    /** @return array{basePath: ?string, minLevel: int} */
    private function captureLogState(): array {
        $basePath = new \ReflectionProperty(Log::class, 'basePath');
        $minLevel = new \ReflectionProperty(Log::class, 'minLevel');

        return [
            'basePath' => $basePath->getValue(),
            'minLevel' => $minLevel->getValue(),
        ];
    }

    /** @param array{basePath: ?string, minLevel: int} $state */
    private function restoreLogState(array $state): void {
        $basePath = new \ReflectionProperty(Log::class, 'basePath');
        $minLevel = new \ReflectionProperty(Log::class, 'minLevel');
        $basePath->setValue(null, $state['basePath']);
        $minLevel->setValue(null, $state['minLevel']);
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

    public function testMidnightCrossingTimeWindowDeterministic(): void {
        $task = (new TickTask('night_window'))
            ->between('23:00', '02:00');

        self::assertTrue($task->inTimeWindow('23:00'));
        self::assertTrue($task->inTimeWindow('01:59'));
        self::assertFalse($task->inTimeWindow('02:00'));
        self::assertFalse($task->inTimeWindow('22:59'));
    }

    public function testNormalTimeWindowDeterministicOverride(): void {
        $task = (new TickTask('day_window'))
            ->between('03:00', '05:00');

        self::assertFalse($task->inTimeWindow('02:59'));
        self::assertTrue($task->inTimeWindow('03:00'));
        self::assertTrue($task->inTimeWindow('04:59'));
        self::assertFalse($task->inTimeWindow('05:00'));
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

    public function testCommandTimeoutGracefulKill(): void {
        $tick = new Tick($this->cacheDir);
        $task = $tick->task('timeout_test')
            ->every(1)
            ->command(PHP_BINARY . ' -r "sleep(30);"', 1);

        $result = $task->execute();

        self::assertFalse($result['success']);
        self::assertStringContainsString('timeout', strtolower($result['error'] ?? ''));
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

    public function testTaskFailureIsLogged(): void {
        $state = $this->captureLogState();
        $basePath = new \ReflectionProperty(Log::class, 'basePath');
        $basePath->setValue(null, null);

        $tick = new Tick($this->cacheDir);
        $task = $tick->task('log-fail-test')
            ->every(1)
            ->run(function(): void {
                throw new \RuntimeException('Task kaboom');
            });

        $logFile = $this->cacheDir . '/php_errors.log';
        $oldErrorLog = ini_set('error_log', $logFile);

        try {
            $result = $task->execute();
        } finally {
            ini_set('error_log', $oldErrorLog !== false ? $oldErrorLog : '');
            $this->restoreLogState($state);
        }

        self::assertFalse($result['success']);
        self::assertSame('Task kaboom', $result['error']);
        self::assertFileExists($logFile);
        $content = (string) file_get_contents($logFile);
        self::assertStringContainsString('Task kaboom', $content);
        self::assertStringContainsString('log-fail-test', $content);
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

    public function testCustomThrottleConstructorArg(): void {
        $tick = new Tick($this->cacheDir, throttleSeconds: 1);
        $counter = 0;

        $tick->task('custom_throttle')
            ->every(0)
            ->run(function() use (&$counter) { $counter++; });

        $tick->dispatch();
        self::assertSame(1, $counter);

        $tick->dispatch();
        self::assertSame(1, $counter);

        usleep(1_100_000);
        $tick->dispatch();
        self::assertSame(2, $counter);
    }

    public function testPrefixIsolationStateForTwoCacheDirs(): void {
        $cacheDirA = $this->createCacheDir('pframe_tick_a_');
        $cacheDirB = $this->createCacheDir('pframe_tick_b_');
        $counterA = 0;
        $counterB = 0;

        $tickA = new Tick($cacheDirA);
        $tickA->task('shared')
            ->every(3600)
            ->run(function() use (&$counterA) { $counterA++; });

        $tickB = new Tick($cacheDirB);
        $tickB->task('shared')
            ->every(3600)
            ->run(function() use (&$counterB) { $counterB++; });

        $tickA->dispatch(forceRun: true);
        $tickB->dispatch(forceRun: true);

        self::assertSame(1, $counterA);
        self::assertSame(1, $counterB);
    }

    public function testLockPreventsExecutionWhenLockHeld(): void {
        $tick = new Tick($this->cacheDir);
        $counter = 0;

        $tick->task('locked')
            ->every(1)
            ->run(function() use (&$counter) { $counter++; });

        $lockPath = $this->lockPath($this->cacheDir, 'locked');
        $handle = fopen($lockPath, 'c');
        self::assertNotFalse($handle);
        if ($handle === false) {
            return;
        }

        try {
            self::assertTrue(flock($handle, LOCK_EX | LOCK_NB));
            $results = $tick->dispatch(forceRun: true);
            self::assertSame(0, $counter);
            self::assertSame([], $results);
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
            @unlink($lockPath);
        }
    }

    public function testTickLogsWhenStateDirectoryIsNotWritable(): void {
        $tick = new Tick('/proc/fake/tick_dir_' . uniqid('', true));
        $tick->task('io-fail-test')
            ->every(1)
            ->run(function(): void {});

        $logFile = $this->cacheDir . '/tick_io_errors.log';
        $oldErrorLog = ini_set('error_log', $logFile);

        try {
            $results = $tick->dispatch();
        } finally {
            ini_set('error_log', $oldErrorLog !== false ? $oldErrorLog : '');
        }

        self::assertSame([], $results);
        self::assertFileExists($logFile);
        $content = (string) file_get_contents($logFile);
        self::assertStringContainsString('Tick: cannot open', $content);
        self::assertStringContainsString('io-fail-test', $content);
    }

    public function testFailedTaskRetriesThenSucceeds(): void {
        $tick = new Tick($this->cacheDir);
        $attempts = 0;

        $tick->task('retry_then_success')
            ->every(3600)
            ->retries(3)
            ->run(function() use (&$attempts) {
                $attempts++;
                if ($attempts < 3) {
                    throw new \RuntimeException('not yet');
                }
            });

        $res1 = $tick->dispatch(forceRun: true);
        $res2 = $tick->dispatch(forceRun: true);
        $res3 = $tick->dispatch(forceRun: true);
        $res4 = $tick->dispatch(forceRun: true);

        self::assertFalse($res1['retry_then_success']['success']);
        self::assertFalse($res2['retry_then_success']['success']);
        self::assertTrue($res3['retry_then_success']['success']);
        self::assertSame(3, $attempts);
        self::assertSame([], $res4);
    }

    public function testExhaustedRetriesWaitsFullInterval(): void {
        $tick = new Tick($this->cacheDir);
        $attempts = 0;

        $tick->task('always_fail')
            ->every(3600)
            ->retries(2)
            ->run(function() use (&$attempts) {
                $attempts++;
                throw new \RuntimeException('still failing');
            });

        $res1 = $tick->dispatch(forceRun: true);
        $res2 = $tick->dispatch(forceRun: true);
        $res3 = $tick->dispatch(forceRun: true);

        self::assertFalse($res1['always_fail']['success']);
        self::assertFalse($res2['always_fail']['success']);
        self::assertSame([], $res3);
        self::assertSame(2, $attempts);
    }

    public function testSuccessResetsFailCount(): void {
        $tick = new Tick($this->cacheDir);
        $attempts = 0;

        $tick->task('reset_fail_count')
            ->every(1)
            ->retries(2)
            ->run(function() use (&$attempts) {
                $attempts++;
                if ($attempts === 2) {
                    return;
                }
                throw new \RuntimeException('fail ' . $attempts);
            });

        $res1 = $tick->dispatch(forceRun: true);
        $res2 = $tick->dispatch(forceRun: true);
        usleep(1_100_000);
        $res3 = $tick->dispatch(forceRun: true);
        $res4 = $tick->dispatch(forceRun: true);
        $failPath = $this->failPath($this->cacheDir, 'reset_fail_count');

        self::assertFalse($res1['reset_fail_count']['success']);
        self::assertTrue($res2['reset_fail_count']['success']);
        self::assertFileDoesNotExist($failPath);
        self::assertFalse($res3['reset_fail_count']['success']);
        self::assertFalse($res4['reset_fail_count']['success']);
        self::assertSame(4, $attempts);
    }
}
