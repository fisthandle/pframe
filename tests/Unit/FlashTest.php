<?php
declare(strict_types=1);

namespace PFrame\Tests\Unit;

use PFrame\Flash;
use PHPUnit\Framework\TestCase;

class FlashTest extends TestCase {
    protected function setUp(): void {
        $_SESSION = [];
    }

    public function testAddAndGet(): void {
        $flash = new Flash();
        $flash->add('success', 'Saved!');
        $flash->add('error', 'Oops');

        $msgs = $flash->get();
        $this->assertCount(2, $msgs);
        $this->assertSame('success', $msgs[0]['type']);
    }

    public function testGetClearsMessages(): void {
        $flash = new Flash();
        $flash->add('info', 'Note');
        $flash->get();
        $this->assertEmpty($flash->get());
    }

    public function testRepeatedMessageIsStoredOncePerType(): void {
        $flash = new Flash();
        $flash->info('Saved');
        $flash->info('Saved');
        $flash->success('Saved');

        $this->assertSame([
            ['type' => 'info', 'text' => 'Saved'],
            ['type' => 'success', 'text' => 'Saved'],
        ], $flash->get());
    }

    public function testStorageKeepsNewestMessagesWithinSessionBudget(): void {
        $flash = new Flash();
        $texts = [];
        for ($i = 0; $i < 8; $i++) {
            $texts[] = $i . str_repeat('x', 4096);
            $flash->info($texts[$i]);
        }

        $this->assertLessThanOrEqual(16384, strlen(serialize($_SESSION['_flash_messages'])));
        $this->assertSame(array_slice($texts, -3), array_column($flash->get(), 'text'));
    }

    public function testMessageLargerThanSessionBudgetIsDiscarded(): void {
        $flash = new Flash();
        $flash->info(str_repeat('x', 16384));

        $this->assertFalse($flash->has());
        $this->assertSame([], $flash->get());
    }

    public function testHas(): void {
        $flash = new Flash();
        $this->assertFalse($flash->has());
        $flash->add('info', 'x');
        $this->assertTrue($flash->has());
    }

    public function testCorruptedMessagesAreDiscarded(): void {
        $_SESSION['_flash_messages'] = [
            'invalid',
            ['type' => 'success'],
            ['type' => 'info', 'text' => 'valid'],
        ];

        $flash = new Flash();
        $this->assertTrue($flash->has());
        $this->assertSame([['type' => 'info', 'text' => 'valid']], $flash->get());
    }

    public function testAddReplacesInvalidStorage(): void {
        $_SESSION['_flash_messages'] = 'invalid';

        $flash = new Flash();
        $flash->success('saved');

        $this->assertSame([['type' => 'success', 'text' => 'saved']], $flash->get());
    }

    public function testConvenienceMethods(): void {
        $flash = new Flash();
        $flash->success('ok');
        $flash->warning('warn');
        $flash->error('err');
        $flash->info('info');

        $types = array_column($flash->get(), 'type');
        $this->assertSame(['success', 'warning', 'error', 'info'], $types);
    }
}
