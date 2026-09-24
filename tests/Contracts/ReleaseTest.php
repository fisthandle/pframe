<?php
declare(strict_types=1);

namespace PFrame\Tests\Contracts;

use PHPUnit\Framework\TestCase;

class ReleaseTest extends TestCase {
    private string $devDir;

    protected function setUp(): void {
        $this->devDir = sys_get_temp_dir() . '/pframe_release_contract_' . bin2hex(random_bytes(6));
        $root = dirname(__DIR__, 2);
        $this->sh(<<<SH
            set -e
            dev='{$this->devDir}'
            mkdir -p "\$dev/pframe/bin" "\$dev/pframe/src"
            cp '{$root}/bin/release' '{$root}/bin/consumers.sh' "\$dev/pframe/bin/"
            printf '#!/bin/sh\\nexit 0\\n' > "\$dev/pframe/bin/test"; chmod +x "\$dev/pframe/bin/test"
            echo '{"scripts":{"phpstan":"true"}}' > "\$dev/pframe/composer.json"
            echo '<?php // v2' > "\$dev/pframe/src/PFrame.php"
            echo '<?php // testing v2' > "\$dev/pframe/src/PFrameTesting.php"
            git init --quiet -b main "\$dev/pframe"
            git -C "\$dev/pframe" add -A && git -C "\$dev/pframe" commit --quiet -m 'Release subject'
            git init --quiet --bare "\$dev/origin.git"
            git -C "\$dev/pframe" remote add origin "\$dev/origin.git"
            git -C "\$dev/pframe" push --quiet origin main
            for consumer in good broken dirty; do
                mkdir -p "\$dev/\$consumer/lib"
                echo '<?php // v1' > "\$dev/\$consumer/lib/PFrame.php"
                result=true; [ "\$consumer" = broken ] && result=false
                echo "{\\"scripts\\":{\\"test\\":\\"\$result\\"}}" > "\$dev/\$consumer/composer.json"
                git init --quiet "\$dev/\$consumer"
                git -C "\$dev/\$consumer" add -A && git -C "\$dev/\$consumer" commit --quiet -m init
            done
            touch "\$dev/dirty/wip.txt"
            SH);
    }

    protected function tearDown(): void {
        $this->sh("rm -rf '{$this->devDir}'");
    }

    public function testReleasesPassingConsumersAndLeavesFailingOrDirtyOnesUntouched(): void {
        $result = $this->sh("'{$this->devDir}/pframe/bin/release'");

        $this->assertSame(1, $result['exit'], $result['output']);
        $this->assertStringContainsString('Niewydane: broken dirty', $result['output']);

        $sha = trim($this->sh("git -C '{$this->devDir}/pframe' rev-parse --short HEAD")['output']);
        $this->assertStringEqualsFile($this->devDir . '/good/lib/PFrame.php', "<?php // v2\n");
        $this->assertSame("Update PFrame to {$sha}\n", $this->sh("git -C '{$this->devDir}/good' log -1 --format=%s")['output']);
        $this->assertSame('', $this->sh("git -C '{$this->devDir}/good' status --porcelain")['output']);

        foreach (['broken', 'dirty'] as $consumer) {
            $this->assertStringEqualsFile($this->devDir . "/{$consumer}/lib/PFrame.php", "<?php // v1\n");
            $this->assertSame("init\n", $this->sh("git -C '{$this->devDir}/{$consumer}' log -1 --format=%s")['output']);
        }
        $this->assertSame('', $this->sh("git -C '{$this->devDir}/broken' status --porcelain")['output']);
    }

    public function testSelectedCurrentConsumerIsANoOpAndUnknownConsumerFails(): void {
        $this->sh("'{$this->devDir}/pframe/bin/release' good");

        $current = $this->sh("'{$this->devDir}/pframe/bin/release' good");
        $this->assertSame(0, $current['exit'], $current['output']);
        $this->assertStringContainsString('good: aktualny', $current['output']);

        $unknown = $this->sh("'{$this->devDir}/pframe/bin/release' broken missing");
        $this->assertSame(1, $unknown['exit'], $unknown['output']);
        $this->assertStringContainsString('Nie znaleziono konsumenta: missing', $unknown['output']);
        $this->assertStringNotContainsString('== broken', $unknown['output']);
    }

    public function testReleasesNestedConsumerInMonorepo(): void {
        $this->sh(<<<SH
            set -e
            repo='{$this->devDir}/mono'
            mkdir -p "\$repo/apps/publisher/lib"
            echo '<?php // v1' > "\$repo/apps/publisher/lib/PFrame.php"
            echo '{"scripts":{"test":"true"}}' > "\$repo/composer.json"
            git init --quiet "\$repo" && git -C "\$repo" add -A && git -C "\$repo" commit --quiet -m init
            SH);

        $result = $this->sh("'{$this->devDir}/pframe/bin/release' mono/apps/publisher");

        $this->assertSame(0, $result['exit'], $result['output']);
        $this->assertStringEqualsFile($this->devDir . '/mono/apps/publisher/lib/PFrame.php', "<?php // v2\n");
        $this->assertSame('', $this->sh("git -C '{$this->devDir}/mono' status --porcelain")['output']);
    }

    public function testRejectedCommitHookRollsBackCopy(): void {
        $this->sh("printf '#!/bin/sh\\nexit 1\\n' > '{$this->devDir}/good/.git/hooks/pre-commit' && chmod +x '{$this->devDir}/good/.git/hooks/pre-commit'");

        $result = $this->sh("'{$this->devDir}/pframe/bin/release' good");

        $this->assertSame(1, $result['exit'], $result['output']);
        $this->assertStringContainsString('BŁĄD commita', $result['output']);
        $this->assertStringEqualsFile($this->devDir . '/good/lib/PFrame.php', "<?php // v1\n");
        $this->assertSame('', $this->sh("git -C '{$this->devDir}/good' status --porcelain")['output']);
    }

    public function testPushWithoutUpstreamSkipsBeforeCopying(): void {
        $result = $this->sh("'{$this->devDir}/pframe/bin/release' --push good");

        $this->assertSame(1, $result['exit'], $result['output']);
        $this->assertStringContainsString('bez upstreamu', $result['output']);
        $this->assertStringEqualsFile($this->devDir . '/good/lib/PFrame.php', "<?php // v1\n");
    }

    public function testRefusesUnpushedPframeCommit(): void {
        $this->sh("cd '{$this->devDir}/pframe' && echo '<?php // v3' > src/PFrame.php && git commit --quiet -am local");

        $result = $this->sh("'{$this->devDir}/pframe/bin/release'");

        $this->assertSame(1, $result['exit'], $result['output']);
        $this->assertStringContainsString('najpierw wypchnij commit', $result['output']);
        $this->assertStringEqualsFile($this->devDir . '/good/lib/PFrame.php', "<?php // v1\n");
    }

    /** @return array{exit: int, output: string} */
    private function sh(string $script): array {
        $env = getenv() + [
            'GIT_AUTHOR_NAME' => 'PFrame Test', 'GIT_AUTHOR_EMAIL' => 'test@example.invalid',
            'GIT_COMMITTER_NAME' => 'PFrame Test', 'GIT_COMMITTER_EMAIL' => 'test@example.invalid',
            'GIT_CONFIG_GLOBAL' => '/dev/null', 'GIT_CONFIG_NOSYSTEM' => '1',
        ];
        $pipes = [];
        $process = proc_open(['bash', '-c', $script], [1 => ['pipe', 'w'], 2 => ['redirect', 1]], $pipes, null, $env);
        $this->assertIsResource($process);
        $output = (string) stream_get_contents($pipes[1]);
        fclose($pipes[1]);

        return ['exit' => proc_close($process), 'output' => $output];
    }
}
