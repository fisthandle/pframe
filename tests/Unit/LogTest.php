<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PFrame\Log;
use PHPUnit\Framework\TestCase;

class LogTest extends TestCase {
    private string $tmpDir;

    protected function setUp(): void {
        $this->tmpDir = sys_get_temp_dir() . '/p1_log_test_' . uniqid('', true);
        mkdir($this->tmpDir);
        Log::init($this->tmpDir, 1);
    }

    protected function tearDown(): void {
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
        $basePath = new \ReflectionProperty(Log::class, 'basePath');
        $basePath->setValue(null, null);

        $logFile = $this->tmpDir . '/php_errors.log';
        $oldErrorLog = ini_set('error_log', $logFile);

        try {
            Log::error('fallback test', ['key' => 'val']);
        } finally {
            ini_set('error_log', $oldErrorLog !== false ? $oldErrorLog : '');
            Log::init($this->tmpDir, 1);
        }

        $this->assertFileExists($logFile);
        $content = (string) file_get_contents($logFile);
        $this->assertStringContainsString('fallback test', $content);
        $this->assertStringContainsString('"key":"val"', $content);
    }

    public function testToFileFallsBackToErrorLogOnWriteFailure(): void {
        Log::init('/proc/fake_not_writable', 1);

        $logFile = $this->tmpDir . '/php_errors.log';
        $oldErrorLog = ini_set('error_log', $logFile);

        try {
            Log::toFile('app.log', 'write-fail test');
        } finally {
            ini_set('error_log', $oldErrorLog !== false ? $oldErrorLog : '');
            Log::init($this->tmpDir, 1);
        }

        $this->assertFileExists($logFile);
        $content = (string) file_get_contents($logFile);
        $this->assertStringContainsString('write-fail test', $content);
    }
}
