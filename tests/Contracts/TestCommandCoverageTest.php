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
        $binDir = dirname(__DIR__, 2) . '/bin';
        copy($binDir . '/check-consumers.sh', $this->tmpDir . '/bin/check-consumers.sh');
        copy($binDir . '/consumers.sh', $this->tmpDir . '/bin/consumers.sh');
        chmod($this->tmpDir . '/bin/check-consumers.sh', 0755);

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
        $this->assertStringContainsString('step=Consumer copies', $full['output']);
        $this->assertSame(
            ['test:unit', 'test:integration', 'test:contracts', 'phpstan'],
            $this->loggedCommands(),
        );
    }

    public function testFullFailsForStaleTrackedNestedConsumerBeyondPreviousDepthLimit(): void {
        $consumerRoot = $this->tmpDir . '/mono';
        $this->createTrackedConsumer($consumerRoot, 'apps/publisher/lib/PFrame.php');

        $result = $this->runRunner('full', ['PFRAME_CONSUMER_ROOT' => $this->tmpDir]);

        $this->assertSame(1, $result['exit'], $result['output']);
        $this->assertStringContainsString('Some consumers are outdated.', $result['output']);
        $this->assertSame(['test:unit', 'test:integration', 'test:contracts'], $this->loggedCommands());
    }

    public function testContractsChecksConsumerWhenRootIsItsGitRepository(): void {
        $consumerRoot = $this->tmpDir . '/mono';
        $this->createTrackedConsumer($consumerRoot, 'lib/PFrame.php');

        $result = $this->runRunner('contracts', ['PFRAME_CONSUMER_ROOT' => $consumerRoot]);

        $this->assertSame(1, $result['exit'], $result['output']);
        $this->assertStringContainsString('Some consumers are outdated.', $result['output']);
        $this->assertSame(['test:contracts'], $this->loggedCommands());
    }

    public function testContractsIgnoresIgnoredUntrackedConsumerCopy(): void {
        $repo = $this->tmpDir . '/mono';
        mkdir($repo . '/lib', 0777, true);
        file_put_contents($repo . '/.gitignore', "lib/PFrame.php\n");
        file_put_contents($repo . '/lib/PFrame.php', "<?php // stale\n");
        exec('git init --quiet ' . escapeshellarg($repo), $output, $exit);
        $this->assertSame(0, $exit, implode("\n", $output));

        $result = $this->runRunner('contracts', ['PFRAME_CONSUMER_ROOT' => $this->tmpDir]);

        $this->assertSame(0, $result['exit'], $result['output']);
        $this->assertStringContainsString('No external consumer copies found', $result['output']);
        $this->assertSame(['test:contracts'], $this->loggedCommands());
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

    public function testMutationFailsClearlyWhenToolOrCoverageDriverIsUnavailable(): void {
        $missingTool = $this->runRunner('mutation');
        $this->assertSame(1, $missingTool['exit'], $missingTool['output']);
        $this->assertStringContainsString('Mutation tool unavailable', $missingTool['output']);
        $this->assertStringContainsString('status=fail', $missingTool['output']);

        $toolDir = $this->tmpDir . '/tools/infection/vendor/bin';
        mkdir($toolDir, 0777, true);
        $fakeInfection = $toolDir . '/infection';
        file_put_contents($fakeInfection, "#!/usr/bin/env bash\nexit 0\n");
        chmod($fakeInfection, 0755);

        $missingCoverage = $this->runRunner('mutation', ['PFRAME_FORCE_NO_COVERAGE' => '1']);
        $this->assertSame(1, $missingCoverage['exit'], $missingCoverage['output']);
        $this->assertStringContainsString('Mutation coverage driver unavailable', $missingCoverage['output']);
        $this->assertStringContainsString('status=fail', $missingCoverage['output']);
    }

    public function testMutationRunnerPassesOptionsUnderNicenessAndRepositoryLock(): void {
        $toolDir = $this->tmpDir . '/tools/infection/vendor/bin';
        mkdir($toolDir, 0777, true);
        $fakeInfection = $toolDir . '/infection';
        file_put_contents($fakeInfection, '');
        chmod($fakeInfection, 0755);

        $fakePhp = $this->tmpDir . '/fake-bin/php';
        file_put_contents($fakePhp, <<<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == "-r" ]]; then
    exit 0
fi
printf '%s\0' "$@" > "$PFRAME_CAPTURE_ARGS"
ps -o ni= -p "$$" > "$PFRAME_CAPTURE_NICE"
if flock -n "$PFRAME_EXPECT_LOCK_PATH" -c true; then
    echo unlocked > "$PFRAME_CAPTURE_LOCK"
else
    echo locked > "$PFRAME_CAPTURE_LOCK"
fi
SH);
        chmod($fakePhp, 0755);

        $captureArgs = $this->tmpDir . '/infection-args';
        $captureNice = $this->tmpDir . '/infection-nice';
        $captureLock = $this->tmpDir . '/infection-lock';
        $lockPath = $this->tmpDir . '/build/infection/.lock';
        $result = $this->runRunner(
            'mutation',
            [
                'PFRAME_CAPTURE_ARGS' => $captureArgs,
                'PFRAME_CAPTURE_NICE' => $captureNice,
                'PFRAME_CAPTURE_LOCK' => $captureLock,
                'PFRAME_EXPECT_LOCK_PATH' => $lockPath,
            ],
            ['--forwarded-option=contract-test'],
        );

        $this->assertSame(0, $result['exit'], $result['output']);
        $this->assertFileExists($lockPath);
        $args = explode("\0", trim((string) file_get_contents($captureArgs), "\0"));
        $this->assertContains('--no-interaction', $args);
        $this->assertContains('--with-uncovered', $args);
        $this->assertContains('--only-covering-test-cases', $args);
        $this->assertContains('--threads=1', $args);
        $this->assertContains('--forwarded-option=contract-test', $args);
        $this->assertContains('--configuration=' . $this->tmpDir . '/infection.json5', $args);
        $this->assertStringContainsString('pcov.enabled=1', implode("\n", $args));
        $this->assertStringContainsString('xdebug.mode=coverage', implode("\n", $args));
        $this->assertSame('19', trim((string) file_get_contents($captureNice)));
        $this->assertSame('locked', trim((string) file_get_contents($captureLock)));

        $infectionConfig = file_get_contents(dirname(__DIR__, 2) . '/infection.json5');
        $this->assertIsString($infectionConfig);
        $this->assertStringContainsString('"customPath": "tools/infection/phpunit.php"', $infectionConfig);
    }

    public function testMutationPhpUnitIsolatesItsProcessGroupAndPreservesPhpOptions(): void {
        if (!function_exists('posix_getpgrp')) {
            $this->markTestSkipped('POSIX process isolation is unavailable.');
        }

        $toolDir = $this->tmpDir . '/tools/infection';
        mkdir($toolDir . '/vendor/bin', 0777, true);
        copy(dirname(__DIR__, 2) . '/tools/infection/phpunit.php', $toolDir . '/phpunit.php');
        file_put_contents($toolDir . '/vendor/bin/phpunit', <<<'PHP'
<?php
declare(strict_types=1);
echo json_encode([getmypid(), posix_getpgrp(), ini_get('precision')]);
PHP);

        $process = proc_open(
            [PHP_BINARY, '-d', 'precision=7', $toolDir . '/phpunit.php'],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
        );
        $this->assertIsResource($process);
        $output = stream_get_contents($pipes[1]);
        $error = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $this->assertSame(0, proc_close($process), (string) $error);
        [$pid, $group, $precision] = json_decode((string) $output, true, flags: JSON_THROW_ON_ERROR);
        $this->assertSame($pid, $group);
        $this->assertNotSame(posix_getpgrp(), $group);
        $this->assertSame('7', $precision);
    }

    public function testUnsupportedAndUnknownProfilesHaveStableExitCodes(): void {
        foreach (['e2e', 'ui'] as $profile) {
            $result = $this->runRunner($profile);
            $this->assertSame(2, $result['exit'], $result['output']);
            $this->assertStringContainsString('unsupported', $result['output']);
        }

        $unknown = $this->runRunner('unknown');
        $this->assertSame(1, $unknown['exit'], $unknown['output']);
        $this->assertStringContainsString('Usage:', $unknown['output']);
    }

    /**
     * @param array<string, string> $extraEnv
     * @return array{exit: int, output: string}
     */
    private function runRunner(string $profile, array $extraEnv = [], array $arguments = []): array {
        $environment = getenv();
        if (!is_array($environment)) {
            $environment = [];
        }
        $environment = array_merge($environment, [
            'PATH' => $this->tmpDir . '/fake-bin:' . (getenv('PATH') ?: '/usr/bin:/bin'),
            'PFRAME_TEST_COMMAND_LOG' => $this->commandLog,
            'PFRAME_CONSUMER_ROOT' => $this->tmpDir,
        ], $extraEnv);

        $pipes = [];
        $process = proc_open(
            [$this->runner, $profile, ...$arguments],
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

    private function createTrackedConsumer(string $repo, string $relativeCopyPath): void {
        mkdir(dirname($repo . '/' . $relativeCopyPath), 0777, true);
        file_put_contents($this->tmpDir . '/src/PFrame.php', "<?php // canonical\n");
        file_put_contents($repo . '/' . $relativeCopyPath, "<?php // stale\n");

        exec('git init --quiet ' . escapeshellarg($repo), $output, $exit);
        $this->assertSame(0, $exit, implode("\n", $output));
        exec('git -C ' . escapeshellarg($repo) . ' add -- ' . escapeshellarg($relativeCopyPath), $output, $exit);
        $this->assertSame(0, $exit, implode("\n", $output));
    }
}
