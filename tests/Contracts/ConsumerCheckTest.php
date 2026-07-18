<?php
declare(strict_types=1);

namespace PFrame\Tests\Contracts;

use PHPUnit\Framework\TestCase;

class ConsumerCheckTest extends TestCase {
    private string $tmpDir;
    private string $script;
    private string $sourceDir;

    protected function setUp(): void {
        $this->tmpDir = sys_get_temp_dir() . '/pframe_consumers_contract_' . bin2hex(random_bytes(6));
        mkdir($this->tmpDir, 0777, true);
        $this->script = dirname(__DIR__, 2) . '/bin/check-consumers.sh';
        $this->sourceDir = dirname(__DIR__, 2) . '/src';
    }

    protected function tearDown(): void {
        $this->removeTree($this->tmpDir);
    }

    public function testCurrentConsumersInBothSupportedLayoutsPass(): void {
        $this->copyConsumer('first/lib');
        $this->copyConsumer('second/app/lib');

        $result = $this->runCheck();

        $this->assertSame(0, $result['exit'], $result['output']);
        $this->assertStringContainsString('All consumers up to date.', $result['output']);
        $this->assertSame(4, substr_count($result['output'], 'CURRENT'));
    }

    public function testOutdatedConsumerFails(): void {
        $dir = $this->copyConsumer('outdated/lib');
        file_put_contents($dir . '/PFrame.php', "\n// stale\n", FILE_APPEND);

        $result = $this->runCheck();

        $this->assertSame(1, $result['exit'], $result['output']);
        $this->assertStringContainsString('OUTDATED', $result['output']);
        $this->assertStringContainsString('Synchronize them from', $result['output']);
    }

    public function testNoConsumersIsAnExplicitFailure(): void {
        $result = $this->runCheck();

        $this->assertSame(2, $result['exit'], $result['output']);
        $this->assertStringContainsString('No consumers found', $result['output']);
    }

    private function copyConsumer(string $relativeDir): string {
        $dir = $this->tmpDir . '/' . $relativeDir;
        mkdir($dir, 0777, true);
        copy($this->sourceDir . '/PFrame.php', $dir . '/PFrame.php');
        copy($this->sourceDir . '/PFrameTesting.php', $dir . '/PFrameTesting.php');
        return $dir;
    }

    /** @return array{exit: int, output: string} */
    private function runCheck(): array {
        $pipes = [];
        $process = proc_open(
            [$this->script, $this->tmpDir],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            dirname(__DIR__, 2),
        );
        $this->assertIsResource($process);

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exit = proc_close($process);

        return ['exit' => $exit, 'output' => (string) $stdout . (string) $stderr];
    }

    private function removeTree(string $path): void {
        if (!is_dir($path)) {
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST,
        );
        foreach ($iterator as $item) {
            if ($item->isDir()) {
                rmdir($item->getPathname());
            } else {
                unlink($item->getPathname());
            }
        }
        rmdir($path);
    }
}
