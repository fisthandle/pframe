<?php
declare(strict_types=1);

namespace PFrame\Testing;

use PFrame\App;
use PFrame\Base;
use PFrame\Csrf;
use PFrame\Request;
use PFrame\Response;
use PHPUnit\Framework\TestCase as PHPUnitTestCase;

trait DatabaseTransactions {
    protected function setUpDatabaseTransactions(): void {
        Base::db()->begin();
    }

    protected function tearDownDatabaseTransactions(): void {
        if (Base::db()->trans()) {
            Base::db()->rollback();
        }
    }
}

trait DatabaseAssertions {
    protected function assertDatabaseHas(string $table, array $conditions): void {
        [$where, $params] = $this->buildWhereClause($conditions);
        $row = Base::row("SELECT 1 FROM $table WHERE $where LIMIT 1", $params);
        $this->assertNotNull($row, "No row in '$table' matching " . json_encode($conditions));
    }

    protected function assertDatabaseMissing(string $table, array $conditions): void {
        [$where, $params] = $this->buildWhereClause($conditions);
        $row = Base::row("SELECT 1 FROM $table WHERE $where LIMIT 1", $params);
        $this->assertNull($row, "Unexpected row in '$table' matching " . json_encode($conditions));
    }

    protected function assertDatabaseCount(string $table, int $expected, array $conditions = []): void {
        [$where, $params] = $this->buildWhereClause($conditions);
        $count = (int) Base::var("SELECT COUNT(*) FROM $table WHERE $where", $params);
        $scope = $conditions === [] ? "'$table'" : "'$table' matching " . json_encode($conditions);
        $this->assertSame($expected, $count, "Expected $expected rows in $scope, got $count");
    }

    /** @return array{0: string, 1: list<mixed>} */
    private function buildWhereClause(array $conditions): array {
        if ($conditions === []) {
            return ['1=1', []];
        }
        $where = [];
        $params = [];
        foreach ($conditions as $col => $val) {
            if ($val === null) {
                $where[] = "$col IS NULL";
            } else {
                $where[] = "$col = ?";
                $params[] = $val;
            }
        }
        return [implode(' AND ', $where), $params];
    }
}

trait ActingAs {
    protected function sessionUserKey(): string {
        return 'user';
    }

    protected function actingAs(array $user): void {
        $_SESSION[$this->sessionUserKey()] = $user;
    }

    protected function actingAsGuest(): void {
        unset($_SESSION[$this->sessionUserKey()]);
    }
}

trait ResponseAssertions {
    protected Response $response;

    protected function assertStatus(int $expected): void {
        $this->assertSame($expected, $this->response->status, "Expected status $expected, got {$this->response->status}");
    }

    protected function assertOk(): void {
        $this->assertStatus(200);
    }

    protected function assertNotFound(): void {
        $this->assertStatus(404);
    }

    protected function assertForbidden(): void {
        $this->assertStatus(403);
    }

    protected function assertUnauthorized(): void {
        $this->assertStatus(401);
    }

    protected function assertRedirect(?string $url = null): void {
        $this->assertTrue(
            $this->response->status >= 300 && $this->response->status < 400,
            "Expected redirect (3xx), got {$this->response->status}",
        );
        if ($url !== null) {
            $this->assertRedirectTo($url);
        }
    }

    protected function assertRedirectTo(string $url): void {
        $this->assertRedirect();
        $location = $this->response->headers['Location'] ?? '';
        $this->assertSame($url, $location, "Expected redirect to '$url', got '$location'");
    }

    protected function assertSee(string $text): void {
        $this->assertStringContainsString($text, $this->response->body, "Response body does not contain '$text'");
    }

    protected function assertDontSee(string $text): void {
        $this->assertStringNotContainsString($text, $this->response->body, "Response body should not contain '$text'");
    }

    protected function assertJsonContains(array $expected): void {
        $actual = json_decode($this->response->body, true);
        $this->assertNotNull($actual, 'Response body is not valid JSON');
        foreach ($expected as $key => $value) {
            $this->assertArrayHasKey($key, $actual, "JSON missing key '$key'");
            $this->assertSame(
                $value,
                $actual[$key],
                "JSON key '$key': expected " . var_export($value, true) . ', got ' . var_export($actual[$key], true),
            );
        }
    }

    protected function assertHeader(string $name, ?string $value = null): void {
        $this->assertArrayHasKey($name, $this->response->headers, "Header '$name' not found in response");
        if ($value !== null) {
            $this->assertSame(
                $value,
                $this->response->headers[$name],
                "Header '$name': expected '$value', got '{$this->response->headers[$name]}'",
            );
        }
    }

    protected function assertHeaderMissing(string $name): void {
        $this->assertArrayNotHasKey($name, $this->response->headers, "Header '$name' should not be present");
    }
}

trait HttpTesting {
    protected App $app;
    private bool $withCsrf = true;
    private array $extraHeaders = [];

    protected function get(string $path, array $query = []): Response {
        return $this->call('GET', $path, query: $query);
    }

    protected function post(string $path, array $data = []): Response {
        return $this->call('POST', $path, post: $data);
    }

    protected function put(string $path, array $data = []): Response {
        return $this->call('PUT', $path, post: $data);
    }

    protected function patch(string $path, array $data = []): Response {
        return $this->call('PATCH', $path, post: $data);
    }

    protected function delete(string $path, array $data = []): Response {
        return $this->call('DELETE', $path, post: $data);
    }

    protected function postJson(string $path, array $data = []): Response {
        $this->extraHeaders['Content-Type'] = 'application/json';
        $this->extraHeaders['X-Requested-With'] = 'XMLHttpRequest';
        return $this->call('POST', $path, body: json_encode($data, JSON_THROW_ON_ERROR));
    }

    protected function withHeaders(array $headers): static {
        $this->extraHeaders = array_merge($this->extraHeaders, $headers);
        return $this;
    }

    protected function withoutCsrf(): static {
        $this->withCsrf = false;
        return $this;
    }

    protected function asAjax(): static {
        $this->extraHeaders['X-Requested-With'] = 'XMLHttpRequest';
        return $this;
    }

    protected function call(
        string $method,
        string $path,
        array $query = [],
        array $post = [],
        string $body = '',
    ): Response {
        $method = strtoupper($method);

        if ($this->withCsrf && in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            $post[Csrf::FIELD_NAME] ??= Csrf::token();
        }

        $request = new Request(
            method: $method,
            path: $path,
            query: $query,
            post: $post,
            headers: $this->extraHeaders,
            body: $body,
        );

        try {
            $this->response = $this->app->handle($request);
        } finally {
            $this->withCsrf = true;
            $this->extraHeaders = [];
        }

        return $this->response;
    }
}

trait FlashAssertions {
    private const FLASH_SESSION_KEY = '_flash_messages';

    protected function assertFlash(string $type, ?string $text = null): void {
        $messages = $_SESSION[self::FLASH_SESSION_KEY] ?? [];
        $found = false;
        foreach ($messages as $message) {
            if (($message['type'] ?? null) !== $type) {
                continue;
            }
            if ($text !== null && ($message['text'] ?? null) !== $text) {
                continue;
            }
            $found = true;
            break;
        }

        $this->assertTrue(
            $found,
            $text !== null
                ? "No flash message of type '$type' with text '$text'"
                : "No flash message of type '$type'",
        );
    }

    protected function assertNoFlash(?string $type = null): void {
        $messages = $_SESSION[self::FLASH_SESSION_KEY] ?? [];
        if ($type === null) {
            $this->assertEmpty($messages, 'Expected no flash messages, but found ' . count($messages));
            return;
        }

        $found = false;
        foreach ($messages as $message) {
            if (($message['type'] ?? null) === $type) {
                $found = true;
                break;
            }
        }
        $this->assertFalse($found, "Unexpected flash message of type '$type'");
    }
}

trait SessionAssertions {
    protected function sessionUserKey(): string {
        return 'user';
    }

    protected function assertAuthenticated(): void {
        $key = $this->sessionUserKey();
        $this->assertNotEmpty($_SESSION[$key] ?? null, 'Expected authenticated user, but session has no user');
    }

    protected function assertGuest(): void {
        $key = $this->sessionUserKey();
        $this->assertEmpty($_SESSION[$key] ?? null, 'Expected guest, but session has user');
    }

    protected function assertSessionHas(string $key, mixed ...$value): void {
        $this->assertArrayHasKey($key, $_SESSION, "Session missing key '$key'");
        if ($value !== []) {
            $this->assertSame(
                $value[0],
                $_SESSION[$key],
                "Session key '$key': expected " . var_export($value[0], true) . ', got ' . var_export($_SESSION[$key], true),
            );
        }
    }

    protected function assertSessionMissing(string $key): void {
        $this->assertArrayNotHasKey($key, $_SESSION, "Session should not have key '$key'");
    }
}

trait RefreshDatabase {
    private static bool $migrated = false;

    abstract protected function migrationPath(): string;

    protected function bootRefreshDatabase(): void {
        if (self::$migrated) {
            return;
        }

        $path = $this->migrationPath();
        $files = glob($path . '/*.sql');
        if ($files === false || $files === []) {
            throw new \RuntimeException("No SQL files found in '$path'");
        }
        sort($files, SORT_NATURAL);

        $db = Base::db();
        foreach ($files as $file) {
            $sql = file_get_contents($file);
            if ($sql === false || trim($sql) === '') {
                continue;
            }
            $db->pdo()->exec($sql);
        }

        self::$migrated = true;
    }
}

class TestCase extends PHPUnitTestCase {
    use DatabaseTransactions, DatabaseAssertions, ResponseAssertions, FlashAssertions;
    use ActingAs, SessionAssertions {
        SessionAssertions::sessionUserKey insteadof ActingAs;
    }

    protected function setUp(): void {
        parent::setUp();
        $_SESSION = [];
        $this->setUpDatabaseTransactions();
    }

    protected function tearDown(): void {
        $this->tearDownDatabaseTransactions();
        $_SESSION = [];
        parent::tearDown();
    }
}
