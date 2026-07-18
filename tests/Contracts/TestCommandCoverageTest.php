<?php
declare(strict_types=1);

namespace PFrame\Tests\Contracts;

use PHPUnit\Framework\TestCase;

class TestCommandCoverageTest extends TestCase {
    private string $tmpDir;
    private string $runner;
    private string $commandLog;

    protected function setUp(): void {
        $this->tmpDir = sys_get_temp_dir() . '/pframe_runner_contract_' . bin2hex(random_bytes(6));
        mkdir($this->tmpDir . '/bin', 0777, true);
        mkdir($this->tmpDir . '/src');
        mkdir($this->tmpDir . '/tests');
        mkdir($this->tmpDir . '/fake-bin');

        $sourceRunner = dirname(__DIR__, 2) . '/bin/test';
        $this->runner = $this->tmpDir . '/bin/test';
        copy($sourceRunner, $this->runner);
        chmod($this->runner, 0755);

        $fakeComposer = $this->tmpDir . '/fake-bin/composer';
        file_put_contents($fakeComposer, <<<'SH'
#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$PFRAME_TEST_COMMAND_LOG"
if [[ "${PFRAME_FAIL_COMMAND:-}" == "$*" ]]; then
    exit 42
fi
SH);
        chmod($fakeComposer, 0755);
        $this->commandLog = $this->tmpDir . '/commands.log';
    }

    protected function tearDown(): void {
        $this->removeTree($this->tmpDir);
    }

    public function testQuickAndFullExecuteExpectedCommandsInOrder(): void {
        $quick = $this->runRunner('quick');
        $this->assertSame(0, $quick['exit'], $quick['output']);
        $this->assertSame(['test:unit', 'test:integration'], $this->loggedCommands());

        file_put_contents($this->commandLog, '');
        $full = $this->runRunner('full');
        $this->assertSame(0, $full['exit'], $full['output']);
        $this->assertSame(
            ['test:unit', 'test:integration', 'test:contracts', 'phpstan'],
            $this->loggedCommands(),
        );
    }

    public function testRunnerStopsAndFailsWhenACommandFails(): void {
        $result = $this->runRunner('quick', ['PFRAME_FAIL_COMMAND' => 'test:unit']);

        $this->assertSame(1, $result['exit'], $result['output']);
        $this->assertStringContainsString('status=fail', $result['output']);
        $this->assertSame(['test:unit'], $this->loggedCommands());
    }

    public function testCiFailsWhenCoverageDriverIsUnavailable(): void {
        $result = $this->runRunner('ci', ['PFRAME_FORCE_NO_COVERAGE' => '1']);

        $this->assertSame(1, $result['exit'], $result['output']);
        $this->assertStringContainsString('Coverage driver unavailable', $result['output']);
        $this->assertStringContainsString('status=fail', $result['output']);
        $this->assertSame(
            ['test:unit', 'test:integration', 'test:contracts', 'phpstan'],
            $this->loggedCommands(),
        );
    }

    public function testNotApplicableAndUnknownProfilesHaveStableExitCodes(): void {
        foreach (['e2e', 'ui'] as $profile) {
            $result = $this->runRunner($profile);
            $this->assertSame(0, $result['exit'], $result['output']);
            $this->assertStringContainsString('not applicable', $result['output']);
        }

        $unknown = $this->runRunner('unknown');
        $this->assertSame(1, $unknown['exit'], $unknown['output']);
        $this->assertStringContainsString('Usage:', $unknown['output']);
    }

    /**
     * @param array<string, string> $extraEnv
     * @return array{exit: int, output: string}
     */
    private function runRunner(string $profile, array $extraEnv = []): array {
        $environment = getenv();
        if (!is_array($environment)) {
            $environment = [];
        }
        $environment = array_merge($environment, [
            'PATH' => $this->tmpDir . '/fake-bin:' . (getenv('PATH') ?: '/usr/bin:/bin'),
            'PFRAME_TEST_COMMAND_LOG' => $this->commandLog,
        ], $extraEnv);

        $pipes = [];
        $process = proc_open(
            [$this->runner, $profile],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            $this->tmpDir,
            $environment,
        );
        $this->assertIsResource($process);

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exit = proc_close($process);

        return ['exit' => $exit, 'output' => (string) $stdout . (string) $stderr];
    }

    /** @return list<string> */
    private function loggedCommands(): array {
        if (!is_file($this->commandLog)) {
            return [];
        }

        return array_values(array_filter(array_map('trim', file($this->commandLog) ?: [])));
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
