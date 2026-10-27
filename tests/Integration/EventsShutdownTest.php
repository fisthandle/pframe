<?php
declare(strict_types=1);

namespace PFrame\Tests\Integration;

use PHPUnit\Framework\TestCase;

class EventsShutdownTest extends TestCase {
    public function testControllerExitStillWritesRequestLineAfterSessionClose(): void {
        $dir = sys_get_temp_dir() . '/pframe-events-exit-' . bin2hex(random_bytes(4));
        mkdir($dir);
        $script = $dir . '/run.php';
        file_put_contents($script, '<?php
declare(strict_types=1);
require ' . var_export(dirname(__DIR__, 2) . '/src/PFrame.php', true) . ';
final class ExitCtrl {
    public function run(): never {
        $_SESSION["user"] = ["id" => 3];
        http_response_code(201);
        exit;
    }
}
$_SERVER["REQUEST_METHOD"] = "GET";
$_SERVER["REQUEST_URI"] = "/exit/abc123def456ghi";
session_save_path(' . var_export($dir, true) . ');
$app = new PFrame\App();
$app->setConfig("events", ["enabled" => true, "dir" => ' . var_export($dir, true) . ']);
$app->get("/exit/{token}", ExitCtrl::class, "run");
$app->startSession();
register_shutdown_function(static function (): void {
    file_put_contents(' . var_export($dir . '/session-status', true) . ', (string) session_status());
});
$app->run();
');
        try {
            exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($script) . ' 2>&1', $output, $code);
            $files = glob($dir . '/*_events.jsonl') ?: [];
            $this->assertSame(0, $code, implode("\n", $output));
            $this->assertCount(1, $files);
            $line = json_decode((string) file_get_contents($files[0]), true);
            $this->assertIsArray($line);
            $this->assertSame(['http', 'request', 'user:3', 201, '/exit/{token}', ['token' => '[x]']], [$line['category'], $line['action'], $line['actor'], $line['ctx']['status'], $line['ctx']['route'], $line['ctx']['params']]);
            $this->assertSame((string) PHP_SESSION_NONE, file_get_contents($dir . '/session-status'));
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    }

    public function testDisabledLayerKeepsSessionWritesFromLaterShutdownCallbacks(): void {
        $dir = sys_get_temp_dir() . '/pframe-events-off-' . bin2hex(random_bytes(4));
        mkdir($dir);
        $script = $dir . '/run.php';
        file_put_contents($script, '<?php
declare(strict_types=1);
require ' . var_export(dirname(__DIR__, 2) . '/src/PFrame.php', true) . ';
final class ExitCtrl {
    public function run(): never {
        register_shutdown_function(static function (): void {
            $_SESSION["late"] = "kept";
        });
        exit;
    }
}
$_SERVER["REQUEST_METHOD"] = "GET";
$_SERVER["REQUEST_URI"] = "/exit";
session_save_path(' . var_export($dir, true) . ');
session_id("eventsofftest");
$app = new PFrame\App();
$app->get("/exit", ExitCtrl::class, "run");
$app->startSession();
$app->run();
');
        try {
            exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($script) . ' 2>&1', $output, $code);
            $this->assertSame(0, $code, implode("\n", $output));
            $this->assertStringContainsString('late|s:4:"kept"', (string) file_get_contents($dir . '/sess_eventsofftest'));
            $this->assertSame([], glob($dir . '/*_events.jsonl') ?: []);
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    }
}
