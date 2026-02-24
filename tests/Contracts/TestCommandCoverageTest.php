<?php
declare(strict_types=1);

namespace PFrame\Tests\Contracts;

use PHPUnit\Framework\TestCase;

class TestCommandCoverageTest extends TestCase {
    private string $runnerScript;

    protected function setUp(): void {
        $path = dirname(__DIR__, 2) . '/bin/test';
        $content = @file_get_contents($path);

        $this->assertNotFalse($content, 'Cannot read runner script: ' . $path);
        $this->runnerScript = (string) $content;
    }

    public function testRunnerContainsRequiredProfiles(): void {
        $requiredProfiles = [
            'quick)',
            'full)',
            'ci)',
            'coverage)',
            'contracts)',
            'e2e)',
            'ui)',
        ];

        foreach ($requiredProfiles as $profile) {
            $this->assertStringContainsString(
                $profile,
                $this->runnerScript,
                'bin/test missing required profile: ' . $profile
            );
        }
    }

    public function testRunnerContainsRequiredStepLabels(): void {
        $requiredLabels = [
            'Syntax check',
            'Unit tests',
            'Integration tests',
            'Contracts tests',
            'Static analysis (phpstan)',
            'Coverage report',
            'E2E tests (N/A)',
            'UI tests (N/A)',
        ];

        foreach ($requiredLabels as $label) {
            $this->assertStringContainsString(
                $label,
                $this->runnerScript,
                'bin/test missing required label: ' . $label
            );
        }
    }

    public function testRunnerContainsRequiredCommands(): void {
        $requiredCommands = [
            "composer test:unit",
            "composer test:integration",
            "composer test:contracts",
            "composer phpstan",
            "env XDEBUG_MODE=coverage vendor/bin/phpunit --testsuite Unit,Integration,Contracts --coverage-text --coverage-clover build/coverage/clover.xml --coverage-html build/coverage/html",
            "phpdbg -qrr vendor/bin/phpunit --testsuite Unit,Integration,Contracts --coverage-text --coverage-clover build/coverage/clover.xml --coverage-html build/coverage/html",
        ];

        foreach ($requiredCommands as $command) {
            $this->assertStringContainsString(
                $command,
                $this->runnerScript,
                'bin/test missing required command: ' . $command
            );
        }
    }

    public function testRunnerContainsCoverageFallbackMessage(): void {
        $this->assertStringContainsString(
            'Coverage driver unavailable (xdebug/pcov/phpdbg). Skipping coverage artifacts.',
            $this->runnerScript
        );
    }
}
