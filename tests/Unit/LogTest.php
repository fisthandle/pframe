<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PFrame\Log;
use PHPUnit\Framework\TestCase;

class LogTest extends TestCase {
    private string $tmpDir;
    private ?string $originalBasePath;
    private int $originalMinLevel;

    protected function setUp(): void {
        $this->originalBasePath = (new \ReflectionProperty(Log::class, 'basePath'))->getValue();
        $this->originalMinLevel = (new \ReflectionProperty(Log::class, 'minLevel'))->getValue();
        $this->tmpDir = sys_get_temp_dir() . '/p1_log_test_' . uniqid('', true);
        mkdir($this->tmpDir);
        Log::init($this->tmpDir, 1);
    }

    protected function tearDown(): void {
        $this->restoreLogState($this->originalBasePath, $this->originalMinLevel);
        foreach (glob($this->tmpDir . '/*') ?: [] as $file) {
            unlink($file);
        }
        if (is_dir($this->tmpDir)) {
            rmdir($this->tmpDir);
        }
    }

    public function testWritesLogFile(): void {
        Log::info('test message', ['key' => 'val']);
        $files = glob($this->tmpDir . '/*app.log');
        $this->assertIsArray($files);
        $this->assertNotEmpty($files);
        $content = file_get_contents($files[0]);
        $this->assertStringContainsString('INFO test message', (string) $content);
        $this->assertStringContainsString('"key":"val"', (string) $content);
    }

    public function testLevelFiltering(): void {
        Log::init($this->tmpDir, 7);
        Log::debug('should not appear');
        Log::warn('should appear');
        $files = glob($this->tmpDir . '/*app.log');
        $this->assertIsArray($files);
        $this->assertNotEmpty($files);
        $content = file_get_contents($files[0]);
        $this->assertStringNotContainsString('DEBUG', (string) $content);
        $this->assertStringContainsString('WARN', (string) $content);
    }

    public function testOtherLogLevelsAndManualFileWrite(): void {
        Log::trace('t');
        Log::error('e');
        Log::toFile('custom.log', 'x');

        $this->assertNotEmpty(glob($this->tmpDir . '/*custom.log'));
    }

    public function testDefaultFilePeriodIsYearly(): void {
        Log::error('yearly');

        $this->assertFileExists($this->tmpDir . '/' . date('Y') . '_app.log');
    }

    public function testFilePeriodControlsLogFilePrefix(): void {
        Log::init($this->tmpDir, 1, 'y.m');
        Log::error('monthly');
        Log::toFile('perf.jsonl', '{}', prefixTimestamp: false, daily: true);

        $this->assertFileExists($this->tmpDir . '/' . date('y.m') . '_app.log');
        $this->assertFileDoesNotExist($this->tmpDir . '/' . date('Y') . '_app.log');
        $this->assertFileExists($this->tmpDir . '/' . date('Ymd') . '_perf.jsonl');
    }

    public function testToFileRejectsPathTraversal(): void {
        $this->expectException(\InvalidArgumentException::class);
        Log::toFile('../../etc/evil.log', 'pwned');
    }

    public function testToFileRejectsBackslash(): void {
        $this->expectException(\InvalidArgumentException::class);
        Log::toFile('..\\evil.log', 'pwned');
    }

    public function testToFileRejectsNullByte(): void {
        $this->expectException(\InvalidArgumentException::class);
        Log::toFile("evil\0.log", 'pwned');
    }

    public function testErrorFallsBackToErrorLogWhenNotInitialized(): void {
        $logState = $this->logState();
        $this->restoreLogState(null, $logState['minLevel']);

        $logFile = $this->tmpDir . '/php_errors.log';
        $oldErrorLog = ini_set('error_log', $logFile);

        try {
            Log::error('fallback test', ['key' => 'val']);
        } finally {
            ini_set('error_log', $oldErrorLog !== false ? $oldErrorLog : '');
            $this->restoreLogState($logState['basePath'], $logState['minLevel']);
        }

        $this->assertFileExists($logFile);
        $content = (string) file_get_contents($logFile);
        $this->assertStringContainsString('fallback test', $content);
        $this->assertStringContainsString('"key":"val"', $content);
    }

    public function testToFileFallsBackToErrorLogOnWriteFailure(): void {
        $logState = $this->logState();
        Log::init('/proc/fake_not_writable', 1);

        $logFile = $this->tmpDir . '/php_errors.log';
        $oldErrorLog = ini_set('error_log', $logFile);

        try {
            Log::toFile('app.log', 'write-fail test');
        } finally {
            ini_set('error_log', $oldErrorLog !== false ? $oldErrorLog : '');
            $this->restoreLogState($logState['basePath'], $logState['minLevel']);
        }

        $this->assertFileExists($logFile);
        $content = (string) file_get_contents($logFile);
        $this->assertStringContainsString('write-fail test', $content);
    }

    /** @return array{basePath: ?string, minLevel: int} */
    private function logState(): array {
        return [
            'basePath' => (new \ReflectionProperty(Log::class, 'basePath'))->getValue(),
            'minLevel' => (new \ReflectionProperty(Log::class, 'minLevel'))->getValue(),
        ];
    }

    private function restoreLogState(?string $basePath, int $minLevel): void {
        (new \ReflectionProperty(Log::class, 'basePath'))->setValue(null, $basePath);
        (new \ReflectionProperty(Log::class, 'minLevel'))->setValue(null, $minLevel);
        (new \ReflectionProperty(Log::class, 'filePeriod'))->setValue(null, 'Y');
    }
}
