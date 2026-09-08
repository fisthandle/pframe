#!/usr/bin/env php
<?php
declare(strict_types=1);

// Mutated Tick cleanup must not signal the parent Infection process group.
if (!function_exists('posix_setsid') || !function_exists('posix_getpgrp')) {
    fwrite(STDERR, "Mutation tests require POSIX process isolation.\n");
    exit(1);
}

if (posix_getpgrp() !== getmypid() && posix_setsid() === -1) {
    fwrite(STDERR, "Cannot isolate the PHPUnit process group.\n");
    exit(1);
}

require __DIR__ . '/vendor/bin/phpunit';
