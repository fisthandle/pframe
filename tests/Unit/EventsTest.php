<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PFrame\App;
use PFrame\Db;
use PFrame\Events;
use PFrame\Flash;
use PFrame\HttpException;
use PFrame\Request;
use PFrame\Response;
use PFrame\Tick;
use PHPUnit\Framework\TestCase;

class EventsTest extends TestCase {
    private string $dir;

    protected function setUp(): void {
        $this->dir = sys_get_temp_dir() . '/pframe-events-' . bin2hex(random_bytes(4)) . '/';
        mkdir($this->dir);
        $_SESSION = [];
    }

    protected function tearDown(): void {
        Events::disable();
        Events::setActorResolver(null);
        Events::setSessionResolver(null);
        $_SESSION = [];
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    private function app(): App {
        $app = new App();
        $app->setConfig('events.enabled', true);
        $app->setConfig('events.dir', $this->dir);
        return $app;
    }

    /** @return list<array<string, mixed>> */
    private function lines(): array {
        return iterator_to_array(Events::lines(glob($this->dir . '*_events.jsonl*') ?: []), false);
    }

    public function testDisabledLayerWritesNothing(): void {
        $app = new App();
        $app->setConfig('events.dir', $this->dir);
        $app->get('/hello', EventsCtrl::class, 'hello');

        $app->handle(new Request(method: 'GET', path: '/hello'));
        Events::record('auth', 'login');

        $this->assertSame([], glob($this->dir . '*') ?: []);
    }

    public function testRequestLineDescribesRouteOutcomeWritesAndFlash(): void {
        $app = $this->app();
        $app->setDb(new Db(['dsn' => 'sqlite::memory:']));
        $app->db()->exec('CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)');
        $app->route('POST', '/items/{id}/{token}', EventsCtrl::class, 'save');
        $_SESSION['user'] = ['id' => 7];

        $response = $app->handle(new Request(method: 'POST', path: '/items/5/abc123def456ghi', query: ['tab' => 'stare', 'ru' => 'x', 'q' => '<b>'], post: ['_csrf_token' => 't', 'name' => 'Jan', 'password' => 'p']));

        $this->assertSame(302, $response->status);
        [$flash, $line] = $this->lines();
        $this->assertSame(['ui', 'flash_added', 'user:7'], [$flash['category'], $flash['action'], $flash['actor']]);
        $this->assertSame(['type' => 'success', 'text_id' => substr(hash('sha256', 'Zapisano dla jan@x.pl'), 0, 10), 'length' => 21], $flash['ctx']);
        $this->assertSame($flash['request_id'], $line['request_id']);
        $this->assertSame(['web', 'http', 'request', 'user:7', 'ok'], [$line['source'], $line['category'], $line['action'], $line['actor'], $line['outcome']]);
        $this->assertSame([
            'method' => 'POST',
            'route' => '/items/{id}/{token}',
            'status' => 302,
            'params' => ['id' => '5', 'token' => '[x]'],
            'query' => ['tab' => 'stare', 'ru' => '[x]', 'q' => '[x]'],
            'post' => ['name', 'password'],
            'location' => '/items',
            'writes' => ['insert items' => ['rows' => 2, 'ids' => [1, 2]], 'update items' => ['rows' => 1]],
            'rollbacks' => 1,
        ], $line['ctx']);
        $this->assertIsInt($line['duration_ms']);
        $this->assertStringNotContainsString('abc123def456ghi', (string) file_get_contents((glob($this->dir . '*_events.jsonl') ?: [''])[0]));
    }

    public function testUnmatchedAndFailingRequestsAreRecorded(): void {
        $app = $this->app();
        $app->get('/boom', EventsCtrl::class, 'boom');

        $app->handle(new Request(method: 'GET', path: '/reset/abc123def456ghi'));
        $app->handle(new Request(method: 'GET', path: '/boom'));

        [$missing, $boom] = $this->lines();
        $this->assertSame(['route' => null, 'status' => 404, 'path' => '/reset/[x]', 'outcome' => 'rejected'], ['route' => $missing['ctx']['route'], 'status' => $missing['ctx']['status'], 'path' => $missing['ctx']['path'], 'outcome' => $missing['outcome']]);
        $this->assertSame([500, \RuntimeException::class, 'failed'], [$boom['ctx']['status'], $boom['ctx']['exception'], $boom['outcome']]);
    }

    public function testRenderedFlashAndLoginChangeActorAndSession(): void {
        $app = $this->app();
        $app->get('/login', EventsCtrl::class, 'login');
        Events::setSessionResolver(static fn(): string => (string) ($_SESSION['sid'] ?? ''));
        $_SESSION['sid'] = 'anon';
        (new Flash())->add('error', 'Błąd');

        $app->handle(new Request(method: 'GET', path: '/login'));

        $lines = $this->lines();
        $request = $lines[array_key_last($lines)];
        $this->assertSame(['flash_rendered', 'shown'], [$lines[0]['action'], $lines[0]['outcome']]);
        $this->assertSame(['user:9', '', 'anon', 'logged'], [$request['actor'], $request['actor_start'] ?? '', $request['sid'], $request['sid_new']]);
    }

    public function testPersonalDataAndTokensAreMasked(): void {
        $this->assertSame("Mail [email], tel. [num], PESEL [num], val: '[tok]' kwota 120 zł ResponseException", Events::safeText("<b>Mail</b> jan.k+x@wp.pl, tel. +48 601 234 567, PESEL 80010112345, val: '0f9e8d7c6b5a49382716abcdef012345' kwota 120 zł ResponseException"));
        $this->assertSame(['password' => '[x]', 'haslo' => '[x]', 'nested' => ['api_key' => '[x]', 'id' => 5], 'type' => 'email_confirm'], Events::redact(['password' => 'a', 'haslo' => 'b', 'nested' => ['api_key' => 'z', 'id' => 5], 'type' => 'email_confirm']));
        $this->assertSame('/kalendarz/6/[x]/kalendarz.ics', Events::safePath('/kalendarz/6/a1b2c3d4e5f6g7/kalendarz.ics'));
        $this->assertSame(
            ['publication_id' => '0f9e8d7c6b5a49382716abcdef012345', 'error_code' => 'E42', 'assignee_id' => '7', 'apiKey' => '[x]', 'idempotency' => 'k', 'slug' => 'glock-17-gen5-mos-9mm', 'note' => '[text:35]', 'form_title' => 'Nowe ogłoszenie', 'label' => 'Braterstwo API'],
            Events::redact(['publication_id' => '0f9e8d7c6b5a49382716abcdef012345', 'error_code' => 'E42', 'assignee_id' => '7', 'apiKey' => 'z', 'idempotency' => 'k', 'slug' => 'glock-17-gen5-mos-9mm', 'note' => 'id 0f9e8d7c6b5a49382716abcdef012345', 'form_title' => 'Nowe ogłoszenie', 'label' => 'Braterstwo API']),
        );
    }

    public function testWriteKeyRecognisesWriteStatementsOnly(): void {
        $this->assertSame('insert t', Events::writeKey('INSERT INTO `t` (a) VALUES (?)'));
        $this->assertSame('insert t', Events::writeKey('INSERT OR REPLACE INTO t (a) VALUES (?)'));
        $this->assertSame('insert t', Events::writeKey('REPLACE INTO "t" (a) VALUES (?)'));
        $this->assertSame('update t', Events::writeKey(' UPDATE IGNORE t SET a = 1'));
        $this->assertSame('delete r', Events::writeKey('DELETE r FROM r JOIN e ON e.id = r.e'));
        $this->assertNull(Events::writeKey('SELECT 1'));
    }

    public function testTickTaskGetsRunLineWithoutLosingRequestWrites(): void {
        $app = $this->app();
        $app->setDb(new Db(['dsn' => 'sqlite::memory:']));
        $app->db()->exec('CREATE TABLE jobs (id INTEGER PRIMARY KEY)');
        Events::startRun('web');
        Events::recordStatement(0, 'UPDATE jobs SET id = 1', 1, static fn(): string => '0');
        mkdir($this->dir . 'tick');
        $tick = new Tick($this->dir . 'tick', 0);
        $tick->task('cleanup')->every(60)->run(static function () use ($app): void {
            $app->db()->exec('INSERT INTO jobs DEFAULT VALUES');
        });

        $tick->dispatch(true);
        Events::resume(Events::startRun('cli:x'));

        $run = $this->lines()[0];
        $this->assertSame(['cron:cleanup', 'run', 'end', 'ok'], [$run['source'], $run['category'], $run['action'], $run['outcome']]);
        $this->assertSame(['task' => 'cleanup', 'writes' => ['insert jobs' => ['rows' => 1, 'ids' => [1]]]], $run['ctx']);
        $this->assertArrayHasKey('run_id', $run);
    }

    public function testSelectFollowsAnonymousSessionToLoginAndIgnoresOtherActors(): void {
        $rows = [
            ['ts' => '2026-10-27T10:00:00.000+01:00', 'source' => 'web', 'request_id' => 'a', 'sid' => 's1', 'category' => 'http', 'action' => 'request', 'ctx' => ['method' => 'POST', 'route' => '/login', 'status' => 200]],
            ['ts' => '2026-10-27T10:00:00.001+01:00', 'source' => 'web', 'request_id' => 'a', 'sid' => 's1', 'category' => 'ui', 'action' => 'flash_rendered'],
            ['ts' => '2026-10-27T10:01:00.000+01:00', 'source' => 'web', 'request_id' => 'b', 'actor' => 'user:6', 'sid' => 's1', 'sid_new' => 's2', 'category' => 'http', 'action' => 'request', 'ctx' => ['method' => 'POST', 'route' => '/login', 'status' => 302, 'location' => '/profil']],
            ['ts' => '2026-10-27T10:02:00.000+01:00', 'source' => 'web', 'request_id' => 'c', 'sid' => 's3', 'category' => 'http', 'action' => 'request'],
            ['ts' => '2026-10-27T10:03:00.000+01:00', 'source' => 'web', 'request_id' => 'adm', 'actor' => 'user:1', 'sid' => 'sa', 'category' => 'doc', 'action' => 'created', 'subject' => 'doc:5', 'ctx' => ['user' => 'user:6']],
            ['ts' => '2026-10-27T10:04:00.000+01:00', 'source' => 'web', 'request_id' => 'adm2', 'actor' => 'user:1', 'sid' => 'sa', 'category' => 'http', 'action' => 'request'],
            ['ts' => '2026-10-27T10:05:00.000+01:00', 'source' => 'web', 'category' => 'http', 'action' => 'poll', 'ctx' => ['actors' => ['user:6' => 3]]],
        ];
        file_put_contents($this->dir . '20261027_events.jsonl', implode('', array_map(static fn(array $row): string => json_encode($row) . "\n", array_reverse($rows))));

        $selected = Events::select([$this->dir . '20261027_events.jsonl'], 'user:6');
        $ids = array_map(static fn(array $row): string => (string) ($row['request_id'] ?? $row['action']), $selected);
        sort($ids);
        $this->assertSame(['a', 'a', 'adm', 'b', 'poll'], $ids);

        $text = Events::render(Events::select([$this->dir . '20261027_events.jsonl'], '', 'b'));
        $this->assertSame(1, substr_count($text, "\n"));
        $this->assertStringContainsString('user:6 POST /login 302 → /profil', $text);
    }

    public function testWriteFailureNeverBreaksTheRequest(): void {
        $app = $this->app();
        file_put_contents($this->dir . 'not-a-dir', 'x');
        $app->setConfig('events.dir', $this->dir . 'not-a-dir/logs');
        $app->get('/flash', EventsCtrl::class, 'flash');

        $response = $app->handle(new Request(method: 'GET', path: '/flash'));

        $this->assertSame(200, $response->status);
    }

    public function testArchiveIsReplacedOnlyAfterVerification(): void {
        $this->app();
        file_put_contents($this->dir . '20261026_events.jsonl', "{\"request_id\":\"a\"}\n");
        mkdir($this->dir . '20261026_events.jsonl.gz.tmp');

        $this->assertSame('failed=RuntimeException', Events::maintain('20261027', $this->dir));
        $this->assertFileExists($this->dir . '20261026_events.jsonl');
        $this->assertFileDoesNotExist($this->dir . '20261026_events.jsonl.gz');
    }

    public function testRawSavepointsMultipleConnectionsAndReturningAreTracked(): void {
        $this->app();
        $first = new Db(['dsn' => 'sqlite::memory:']);
        $second = new Db(['dsn' => 'sqlite::memory:']);
        foreach ([$first, $second] as $db) {
            $db->exec('CREATE TABLE t (id INTEGER PRIMARY KEY, a TEXT)');
        }
        Events::startRun('cli:test', 'r1');

        $first->begin();
        $first->exec('SAVEPOINT manual');
        $first->exec('INSERT INTO t (a) VALUES (?)', ['gone']);
        $first->exec('ROLLBACK TO SAVEPOINT manual');
        $first->exec('RELEASE SAVEPOINT manual');
        $second->begin();
        $first->exec('INSERT INTO t (a) VALUES (?)', ['kept']);
        $second->exec('INSERT INTO t (a) VALUES (?)', ['dropped']);
        $first->commit();
        $second->rollback();
        $first->row('INSERT INTO t (a) VALUES (?) RETURNING id', ['returned']);
        Events::finishRun();

        $this->assertSame(['writes' => ['insert t' => ['rows' => 2, 'ids' => [1, 2]]], 'rollbacks' => 2], $this->lines()[0]['ctx']);
    }

    public function testFreeTextAndPhoneParametersAreMasked(): void {
        $app = $this->app();
        $app->setConfig('events.mask_params', ['nick']);
        $app->get('/search', EventsCtrl::class, 'hello');

        $app->handle(new Request(method: 'GET', path: '/search', query: ['q' => 'zzprobemarker', 'to' => '601234567', 'nick' => 'jan', 'page' => '2', 'n' => '+48 601 234 567']));

        $this->assertSame(['q' => '[x]', 'to' => '[x]', 'nick' => '[x]', 'page' => '2', 'n' => '[num]'], $this->lines()[0]['ctx']['query']);
    }

    public function testConfigureEnablesProcessesWithoutAppAndChildrenInheritRunId(): void {
        new App();
        Events::configure(['enabled' => true, 'dir' => $this->dir]);
        putenv('PFRAME_RUN_ID=parent-run');
        try {
            Events::startCli('/srv/bin/job.php');
            Events::record('job', 'step', ['n' => 1]);
        } finally {
            putenv('PFRAME_RUN_ID');
            Events::configure(null);
        }

        $line = $this->lines()[0];
        $this->assertSame(['cli:job.php', 'parent-run', 'job', 'step'], [$line['source'], $line['run_id'], $line['category'], $line['action']]);
    }

    public function testSelectIgnoresForeignRequestIdsAndOtherAccountsInTheSameBrowser(): void {
        $rows = [
            ['ts' => '2026-10-27T09:00:00.000+01:00', 'source' => 'web', 'request_id' => 'x', 'actor' => 'user:6', 'sid' => 's6', 'category' => 'http', 'action' => 'request'],
            ['ts' => '2026-10-27T09:00:01.000+01:00', 'source' => 'web', 'request_id' => 'x', 'actor' => 'user:7', 'sid' => 's7', 'category' => 'http', 'action' => 'request'],
            ['ts' => '2026-10-27T09:01:00.000+01:00', 'source' => 'web', 'request_id' => 'a1', 'actor' => 'user:5', 'sid' => 'b1', 'category' => 'http', 'action' => 'request'],
            ['ts' => '2026-10-27T09:02:00.000+01:00', 'source' => 'web', 'request_id' => 'a2', 'actor_start' => 'user:5', 'sid' => 'b1', 'category' => 'http', 'action' => 'request'],
            ['ts' => '2026-10-27T09:03:00.000+01:00', 'source' => 'web', 'request_id' => 'n1', 'sid' => 'b1', 'category' => 'http', 'action' => 'request'],
            ['ts' => '2026-10-27T09:04:00.000+01:00', 'source' => 'web', 'request_id' => 'l6', 'actor' => 'user:6', 'sid' => 'b1', 'sid_new' => 'b2', 'category' => 'http', 'action' => 'request'],
        ];
        file_put_contents($this->dir . '20261027_events.jsonl', implode('', array_map(static fn(array $row): string => json_encode($row) . "\n", $rows)));

        $ids = array_column(Events::select([$this->dir . '20261027_events.jsonl'], 'user:6'), 'request_id');

        $this->assertSame(['x', 'n1', 'l6'], $ids);
    }

    public function testStatsSummariseRoutesOutcomesAndExceptions(): void {
        $rows = [
            ['source' => 'web', 'category' => 'http', 'action' => 'request', 'outcome' => 'ok', 'duration_ms' => 10, 'ctx' => ['method' => 'GET', 'route' => '/a']],
            ['source' => 'web', 'category' => 'http', 'action' => 'request', 'outcome' => 'failed', 'duration_ms' => 90, 'ctx' => ['method' => 'GET', 'route' => '/a', 'exception' => 'RuntimeException']],
            ['source' => 'cron:mail', 'category' => 'run', 'action' => 'end', 'outcome' => 'ok'],
        ];
        file_put_contents($this->dir . '20261027_events.jsonl', implode('', array_map(static fn(array $row): string => json_encode($row) . "\n", $rows)));

        $stats = Events::stats([$this->dir . '20261027_events.jsonl']);

        $this->assertSame(3, $stats['lines']);
        $this->assertSame(['web' => 2, 'cron' => 1], $stats['sources']);
        $this->assertSame(['ok' => 2, 'failed' => 1], $stats['outcomes']);
        $this->assertSame([['route' => 'GET /a', 'count' => 2, 'failed' => 1, 'p95_ms' => 90]], $stats['routes']);
        $this->assertSame(['RuntimeException' => 1], $stats['exceptions']);
    }

    public function testSessionStartFillsRequestActorAndSession(): void {
        $this->app();
        Events::setSessionResolver(static fn(): string => (string) ($_SESSION['sid'] ?? ''));
        Events::beginRequest(true);
        $_SESSION = ['user' => ['id' => 4], 'sid' => 's4'];
        Events::sessionStarted();
        Events::finishRequest(['method' => 'GET', 'path' => '/', 'route' => '/', 'params' => [], 'query' => [], 'post' => [], 'files' => [], 'ajax' => false, 'status' => 200, 'location' => null, 'exception' => null]);

        $line = $this->lines()[0];
        $this->assertSame(['user:4', 's4'], [$line['actor'], $line['sid']]);
        $this->assertArrayNotHasKey('sid_new', $line);
        $this->assertArrayNotHasKey('actor_start', $line);
    }

    public function testCsrfMiddlewareRecordsRejection(): void {
        $app = $this->app();
        $app->route('POST', '/form', EventsCtrl::class, 'hello', [\PFrame\Middleware::csrf()]);

        $this->assertSame(403, $app->handle(new Request(method: 'POST', path: '/form'))->status);

        $this->assertSame(['auth/csrf_failed', 'http/request'], array_map(static fn(array $line): string => $line['category'] . '/' . $line['action'], $this->lines()));
    }

    public function testTickCommandChildInheritsRunId(): void {
        $this->app();
        mkdir($this->dir . 'tick');
        $tick = new Tick($this->dir . 'tick', 0);
        $tick->task('child')->every(60)->command(PHP_BINARY . ' -r ' . escapeshellarg('echo getenv("PFRAME_RUN_ID");'));

        $result = $tick->dispatch(true)['child'];

        $this->assertSame($this->lines()[0]['run_id'], trim((string) ($result['output'] ?? '')));
    }

    public function testWithoutApcuSuccessfulPollsAreDroppedButFailuresKept(): void {
        if (function_exists('apcu_enabled') && apcu_enabled()) {
            $this->markTestSkipped('APCu aggregates polls in this runtime');
        }
        $app = $this->app();
        $app->get('/health', EventsCtrl::class, 'hello');
        $app->get('/boom', EventsCtrl::class, 'boom');
        $app->setConfig('events.aggregate_routes', ['/health', '/boom']);

        $app->handle(new Request(method: 'GET', path: '/health'));
        $app->handle(new Request(method: 'GET', path: '/boom'));

        $this->assertSame(['/boom'], array_map(static fn(array $line): string => $line['ctx']['route'], $this->lines()));
    }

    public function testMissingDirectoryIsCreatedAndDisabledMaintainIsNoop(): void {
        $app = $this->app();
        $app->setConfig('events.dir', $this->dir . 'new/logs');
        Events::startRun('cli:x');
        Events::record('job', 'step');

        $this->assertFileExists($this->dir . 'new/logs/' . date('Ymd') . '_events.jsonl');
        $app->setConfig('events.enabled', false);
        $this->assertSame('disabled', Events::maintain());
    }

    public function testDatesStayReadable(): void {
        $this->assertSame('start 2026-10-27 10:00:00, tel. [num]', Events::safeText('start 2026-10-27 10:00:00, tel. 601234567'));
        $app = $this->app();
        $app->get('/events', EventsCtrl::class, 'hello');
        $app->handle(new Request(method: 'GET', path: '/events', query: ['from' => '2026-10-01', 'to' => '2026-10-31', 'q' => '2026']));
        $this->assertSame(['from' => '2026-10-01', 'to' => '2026-10-31', 'q' => '[x]'], $this->lines()[0]['ctx']['query']);
    }

    public function testRollbackToOuterNamedSavepointDropsNestedWrites(): void {
        $this->app();
        $db = new Db(['dsn' => 'sqlite::memory:']);
        $db->exec('CREATE TABLE t (id INTEGER PRIMARY KEY)');
        Events::startRun('cli:test', 'r1');

        $db->begin();
        $db->exec('SAVEPOINT outer_sp');
        $db->exec('INSERT INTO t DEFAULT VALUES');
        $db->exec('SAVEPOINT inner_sp');
        $db->exec('INSERT INTO t DEFAULT VALUES');
        $db->exec('ROLLBACK TO SAVEPOINT outer_sp');
        $db->exec('INSERT INTO t DEFAULT VALUES');
        $db->exec('RELEASE outer_sp');
        $db->commit();
        Events::finishRun();

        $this->assertSame(1, (int) $db->var('SELECT COUNT(*) FROM t'));
        $this->assertSame(['writes' => ['insert t' => ['rows' => 1, 'ids' => [1]]], 'rollbacks' => 1], $this->lines()[0]['ctx']);
    }

    public function testSelectLinksSessionlessActorsOnlyByActorAndPagesByRequest(): void {
        $rows = [
            ['ts' => '2026-10-27T09:00:00.000+01:00', 'source' => 'web', 'request_id' => 'same', 'actor' => 'api:alice', 'category' => 'http', 'action' => 'request'],
            ['ts' => '2026-10-27T09:00:01.000+01:00', 'source' => 'web', 'request_id' => 'same', 'actor' => 'api:bob', 'category' => 'http', 'action' => 'request'],
            ['ts' => '2026-10-27T09:01:00.000+01:00', 'source' => 'web', 'request_id' => 'pa', 'actor' => 'account:a', 'sid' => 's', 'category' => 'http', 'action' => 'request'],
            ['ts' => '2026-10-27T09:02:00.000+01:00', 'source' => 'web', 'request_id' => 'pb', 'actor' => 'account:b', 'sid' => 's', 'category' => 'http', 'action' => 'request'],
            ['ts' => '2026-10-27T09:03:00.000+01:00', 'source' => 'web', 'request_id' => 'beacon-a', 'sid' => 's', 'category' => 'client', 'action' => 'answer', 'ctx' => ['page_request_id' => 'pa']],
            ['ts' => '2026-10-27T09:04:00.000+01:00', 'source' => 'web', 'request_id' => 'beacon-b', 'sid' => 's', 'category' => 'client', 'action' => 'answer', 'ctx' => ['page_request_id' => 'pb']],
        ];
        file_put_contents($this->dir . '20261027_events.jsonl', implode('', array_map(static fn(array $row): string => json_encode($row) . "\n", $rows)));
        $file = [$this->dir . '20261027_events.jsonl'];

        $this->assertSame(['same'], array_column(Events::select($file, 'api:alice'), 'request_id'));
        $this->assertSame(['pa', 'beacon-a'], array_column(Events::select($file, 'account:a'), 'request_id'));
        $this->assertSame(['pa', 'beacon-a'], array_column(Events::select($file, '', 'pa'), 'request_id'));
    }

    public function testLocationIsLoggedAsRoutePattern(): void {
        $app = $this->app();
        $app->get('/konto/{key}/{step}', EventsCtrl::class, 'hello');
        $app->get('/go', EventsCtrl::class, 'redirectToAccount');

        $app->handle(new Request(method: 'GET', path: '/go'));

        $this->assertSame('/konto/{key}/{step}', $this->lines()[0]['ctx']['location']);
    }

    public function testForgetQueueKeepsEntriesAddedForOpenDays(): void {
        $this->app();
        Events::queueForget('user:1', $this->dir);
        file_put_contents($this->dir . 'events_forget.pending', "user:2|20261026\n", FILE_APPEND);

        Events::maintain(date('Ymd', strtotime('+1 day')), $this->dir);

        $this->assertSame('', file_get_contents($this->dir . 'events_forget.pending'));
        Events::queueForget('user:3', $this->dir);
        $this->assertStringContainsString('user:3|', (string) file_get_contents($this->dir . 'events_forget.pending'));
    }

    public function testManagedAndRawSavepointsStayInSync(): void {
        $this->app();
        $db = new Db(['dsn' => 'sqlite::memory:']);
        $db->exec('CREATE TABLE t (id INTEGER PRIMARY KEY)');
        Events::startRun('cli:test', 'r1');

        $db->begin();
        $db->exec('INSERT INTO t DEFAULT VALUES');
        $db->begin();
        $db->exec('INSERT INTO t DEFAULT VALUES');
        $db->exec('SAVEPOINT manual');
        $db->exec('INSERT INTO t DEFAULT VALUES');
        $db->rollback();
        $db->exec('SAVEPOINT kept');
        $db->exec('INSERT INTO t DEFAULT VALUES');
        $db->exec('ROLLBACK TRANSACTION TO SAVEPOINT kept');
        $db->exec('RELEASE kept');
        $db->commit();
        Events::finishRun();

        $this->assertSame(1, (int) $db->var('SELECT COUNT(*) FROM t'));
        $this->assertSame(['writes' => ['insert t' => ['rows' => 1, 'ids' => [1]]], 'rollbacks' => 2], $this->lines()[0]['ctx']);
    }

    public function testRecordOnCommitFollowsTheTransaction(): void {
        $this->app();
        $db = new Db(['dsn' => 'sqlite::memory:']);
        Events::startRun('cli:test', 'r1');

        Events::recordOnCommit('entity', 'outside');
        $db->begin();
        Events::recordOnCommit('entity', 'kept');
        $db->begin();
        Events::recordOnCommit('entity', 'nested_dropped');
        Events::record('log', 'error');
        $db->rollback();
        $db->commit();
        $db->begin();
        Events::recordOnCommit('entity', 'dropped');
        $db->rollbackAll();

        $this->assertSame(['outside', 'error', 'kept'], array_column($this->lines(), 'action'));
    }

    public function testBeaconFromAnotherSessionIsNotAttachedToPage(): void {
        $rows = [
            ['ts' => '2026-10-27T09:01:00.000+01:00', 'source' => 'web', 'request_id' => 'pa', 'actor' => 'account:a', 'sid' => 's1', 'category' => 'http', 'action' => 'request'],
            ['ts' => '2026-10-27T09:02:00.000+01:00', 'source' => 'web', 'request_id' => 'b1', 'sid' => 's1', 'category' => 'client', 'action' => 'answer', 'ctx' => ['page_request_id' => 'pa']],
            ['ts' => '2026-10-27T09:03:00.000+01:00', 'source' => 'web', 'request_id' => 'b2', 'sid' => 's2', 'category' => 'client', 'action' => 'answer', 'ctx' => ['page_request_id' => 'pa']],
        ];
        file_put_contents($this->dir . '20261027_events.jsonl', implode('', array_map(static fn(array $row): string => json_encode($row) . "\n", $rows)));
        $file = [$this->dir . '20261027_events.jsonl'];

        $this->assertSame(['pa', 'b1'], array_column(Events::select($file, 'account:a'), 'request_id'));
        $this->assertSame(['pa', 'b1'], array_column(Events::select($file, '', 'pa'), 'request_id'));
    }

    public function testForgetQueueSurvivesFailedExpiry(): void {
        $this->app();
        mkdir($this->dir . '20200101_events.jsonl');
        file_put_contents($this->dir . '20200101_events.jsonl/x', 'x');
        file_put_contents($this->dir . 'events_forget.pending', "user:1|20261026\n");

        $this->assertSame('failed=RuntimeException', Events::maintain('20261027', $this->dir));

        $this->assertSame("user:1|20261026\n", file_get_contents($this->dir . 'events_forget.pending'));
        $this->assertSame(['exception' => 'PFrame\\HttpException'], Events::redact(['exception' => 'PFrame\\HttpException']));
    }

    public function testMaintainCompressesPrunesAndForgetsOnlyClosedDays(): void {
        $this->app()->setConfig('events.retention_days', 90);
        $put = fn(string $name, array $rows, bool $gz = false) => file_put_contents($this->dir . $name, ($gz ? 'gzencode' : 'strval')(implode('', array_map(static fn(array $row): string => json_encode($row) . "\n", $rows))));
        $put('20261025_events.jsonl.gz', [
            ['request_id' => 'a', 'actor' => 'user:42'],
            ['request_id' => 'b', 'actor_start' => 'user:42'],
            ['request_id' => 'c', 'subject' => 'doc:7', 'ctx' => ['user' => 'user:42']],
            ['request_id' => 'd', 'action' => 'poll', 'ctx' => ['actors' => ['user:42' => 3]]],
            ['request_id' => 'e', 'action' => 'poll', 'ctx' => ['actors' => ['user:42' => 3, 'user:77' => 5]]],
            ['request_id' => 'f', 'actor' => 'user:420'],
        ], true);
        $put('20261026_events.jsonl', [['request_id' => 'g']]);
        $put('20260701_events.jsonl.gz', [['request_id' => 'old']], true);
        $put('20261027_events.jsonl', [['request_id' => 'today', 'actor' => 'user:42']]);
        file_put_contents($this->dir . 'events_forget.pending', "user:42|20261026\nuser:99|20261027\n");

        $this->assertSame('deleted=1 compressed=1 forgotten_lines=5 forget_pending=1', Events::maintain('20261027', $this->dir));

        $kept = iterator_to_array(Events::lines([$this->dir . '20261025_events.jsonl.gz']), false);
        $this->assertSame(['e', 'f'], array_column($kept, 'request_id'));
        $this->assertSame(['user:77' => 5], $kept[0]['ctx']['actors']);
        $this->assertSame(['20261025_events.jsonl.gz', '20261026_events.jsonl.gz', '20261027_events.jsonl'], array_map('basename', glob($this->dir . '*_events.jsonl*') ?: []));
        $this->assertSame("user:99|20261027\n", file_get_contents($this->dir . 'events_forget.pending'));
    }
}

class EventsCtrl {
    public function hello(): Response {
        return new Response('hi');
    }

    public function save(Request $request, App $app): Response {
        (new Flash())->add('success', 'Zapisano dla jan@x.pl');
        $db = $app->db();
        $db->exec('INSERT INTO items (name) VALUES (?)', ['a']);
        $db->begin();
        $db->exec('INSERT INTO items (name) VALUES (?)', ['b']);
        $db->rollback();
        $db->transaction(static function (Db $db): void {
            $db->exec('INSERT INTO items (name) VALUES (?)', ['c']);
            $db->exec('UPDATE items SET name = ? WHERE id = ?', ['d', 1]);
        });
        $db->exec('SELECT * FROM items');
        return Response::redirect('/items?id=5&ru=secret');
    }

    public function flash(): Response {
        (new Flash())->add('success', 'ok');
        return new Response('ok');
    }

    public function redirectToAccount(): Response {
        return Response::redirect('/konto/shortkey/1');
    }

    public function boom(): Response {
        throw new \RuntimeException('boom');
    }

    public function login(): Response {
        (new Flash())->get();
        $_SESSION['user'] = ['id' => 9];
        $_SESSION['sid'] = 'logged';
        return new Response('ok');
    }
}
