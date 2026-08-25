<?php

declare(strict_types=1);

namespace App\Tests;

use App\Console\DeniedExitCodeListener;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Event\ConsoleCommandEvent;
use Symfony\Component\Console\Tester\ApplicationTester;

/**
 * Drives the guarded commands through the real console Application, so the AccessControl
 * console listener (and the app's console identity listener) actually run.
 */
final class ConsoleAccessControlTest extends KernelTestCase
{
    /**
     * What the console already means by "this command was not allowed to run", and what a denial
     * reports when the application says nothing.
     */
    private const int DENIED = ConsoleCommandEvent::RETURN_CODE_DISABLED; // 113

    /**
     * What DeniedExitCodeListener reports instead, for the two commands that asked for it.
     */
    private const int NO_PERM = DeniedExitCodeListener::EX_NOPERM; // 77

    public function testReportGenerateRequiresAdmin(): void
    {
        $tester = $this->tester();

        self::assertSame(Command::SUCCESS, $tester->run(['command' => 'app:report:generate', '--as' => 'admin']));
        self::assertSame(self::NO_PERM, $tester->run(['command' => 'app:report:generate', '--as' => 'user']));
        // No identity at all: nothing but PUBLIC_ACCESS is granted, so a role is refused.
        self::assertSame(self::NO_PERM, $tester->run(['command' => 'app:report:generate']));
    }

    public function testPurgeOnlyGuardsWhenForced(): void
    {
        $tester = $this->tester();

        // The When condition is false without --force: the policy steps aside, anyone may dry-run.
        self::assertSame(Command::SUCCESS, $tester->run(['command' => 'app:document:purge', '--as' => 'user']));
        // With --force the ROLE_ADMIN policy applies.
        self::assertSame(self::DENIED, $tester->run(['command' => 'app:document:purge', '--force' => true, '--as' => 'user']));
        self::assertSame(Command::SUCCESS, $tester->run(['command' => 'app:document:purge', '--force' => true, '--as' => 'admin']));
    }

    public function testAuditAcceptsEitherRole(): void
    {
        $tester = $this->tester();

        self::assertSame(Command::SUCCESS, $tester->run(['command' => 'app:audit:run', '--as' => 'manager']));
        self::assertSame(Command::SUCCESS, $tester->run(['command' => 'app:audit:run', '--as' => 'admin']));
        self::assertSame(self::NO_PERM, $tester->run(['command' => 'app:audit:run', '--as' => 'user']));
    }

    /**
     * The exit status of a denial is not settable from a policy, and does not need to be: the
     * console owns the question. A listener on ConsoleEvents::ERROR has the last word, because
     * setExitCode() writes the value onto the exception, which is what Application::run() reports.
     *
     * What a setting could not have done is exactly what is measured here — two commands answer
     * one status and the rest answer another, from the same refusal.
     */
    public function testAnApplicationChoosesItsOwnExitStatusPerCommand(): void
    {
        $tester = $this->tester();

        // Listed by DeniedExitCodeListener: the wrappers around these two read 77.
        self::assertSame(self::NO_PERM, $tester->run(['command' => 'app:report:generate', '--as' => 'user']));
        self::assertSame(self::NO_PERM, $tester->run(['command' => 'app:audit:run', '--as' => 'user']));

        // Not listed: the exception's own code stands, and it is the console's number.
        self::assertSame(self::DENIED, $tester->run(['command' => 'app:document:purge', '--force' => true, '--as' => 'user']));
        self::assertNotSame(self::NO_PERM, self::DENIED);
    }

    /**
     * The listener only reads a refusal. A command failing for any other reason keeps the status
     * it was going to report, which is what makes the two distinguishable in a script.
     */
    public function testTheExitStatusIsRewrittenForDenialsAlone(): void
    {
        $tester = $this->tester();

        // An unknown identity throws from the app's own console listener, not from a policy.
        self::assertSame(1, $tester->run(
            ['command' => 'app:report:generate', '--as' => 'nobody'],
            ['capture_stderr_separately' => true],
        ));
    }

    public function testProgrammaticCheckCommandReportsVerdictAndReason(): void
    {
        $tester = $this->tester();

        // A role check that passes.
        $tester->run(['command' => 'app:access:check', 'attribute' => 'ROLE_ADMIN', '--as' => 'admin']);
        self::assertStringContainsString('GRANTED', $tester->getDisplay());

        // A subject-aware check that fails, with the voter's reason surfaced.
        $tester->run(['command' => 'app:access:check', 'attribute' => 'VIEW', 'document' => '2', '--as' => 'user']);
        $display = $tester->getDisplay();
        self::assertStringContainsString('ACCESS_DENIED', $display);
        self::assertStringContainsString('Only the owner or an administrator may view this document.', $display);
    }

    private function tester(): ApplicationTester
    {
        $application = new Application(self::bootKernel());
        $application->setAutoExit(false);

        return new ApplicationTester($application);
    }
}
