<?php
declare(strict_types=1);

namespace PFrame\Tests\Contracts;

use PharData;
use PHPUnit\Framework\TestCase;

class PackagingArchiveTest extends TestCase {
    private string $tmpDir;

    protected function setUp(): void {
        $this->tmpDir = sys_get_temp_dir() . '/pframe_archive_contract_' . bin2hex(random_bytes(6));
        mkdir($this->tmpDir, 0777, true);
    }

    protected function tearDown(): void {
        $this->removeTree($this->tmpDir);
    }

    public function testComposerArchiveContainsOnlyDistributionFiles(): void {
        $projectDir = dirname(__DIR__, 2);
        $pipes = [];
        $process = proc_open(
            [
                'composer',
                'archive',
                '--format=zip',
                '--dir=' . $this->tmpDir,
                '--file=pframe-contract',
                '--no-interaction',
            ],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            $projectDir,
        );
        $this->assertIsResource($process);

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exit = proc_close($process);
        $output = (string) $stdout . (string) $stderr;

        $this->assertSame(0, $exit, $output);

        $archivePath = $this->tmpDir . '/pframe-contract.zip';
        $this->assertFileExists($archivePath, $output);
        $this->assertSame(
            [
                'LICENSE',
                'README.md',
                'composer.json',
                'db/sessions.sql',
                'db/sessions.sqlite.sql',
                'docs/testing-philosophy.md',
                'src/PFrame.php',
                'src/PFrameTesting.php',
            ],
            $this->archiveFiles($archivePath),
        );
    }

    /** @return list<string> */
    private function archiveFiles(string $archivePath): array {
        $archive = new PharData($archivePath);
        $prefix = 'phar://' . $archivePath . '/';
        $files = [];
        $iterator = new \RecursiveIteratorIterator($archive);
        foreach ($iterator as $path => $entry) {
            if ($entry->isFile()) {
                $files[] = substr((string) $path, strlen($prefix));
            }
        }
        sort($files);
        return $files;
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
