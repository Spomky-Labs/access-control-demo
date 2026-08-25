<?php

declare(strict_types=1);

namespace App\Console;

use AccessControl\Exception\AccessDeniedExceptionInterface;
use Symfony\Component\Console\ConsoleEvents;
use Symfony\Component\Console\Event\ConsoleErrorEvent;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

/**
 * What an application writes when 113 is not the exit status its scripts expect.
 *
 * A denial on the console leaves as an exception carrying ConsoleCommandEvent::RETURN_CODE_DISABLED
 * — 113, the number the console already means by "this command was not allowed to run". That value
 * is deliberately not settable from a policy: an exit status is read by the scripts around a
 * command, not by the rule that refused it, which is the same reason no HTTP status is on the
 * attribute either.
 *
 * The way out is the console's own. setExitCode() writes the value onto the exception as well, so
 * Application::run() reports it, and this listener can branch on the command or on who was asking —
 * neither of which a `denied_exit_code` setting would have allowed.
 *
 * Here the reporting commands answer 77, sysexits.h's EX_NOPERM, because the cron wrapper that runs
 * them nightly pages someone on an unknown status and merely logs a permission one. Every other
 * command keeps 113: the listener says nothing, and the exception's own code stands.
 */
#[AsEventListener(ConsoleEvents::ERROR)]
final readonly class DeniedExitCodeListener
{
    /**
     * sysexits.h EX_NOPERM: "permission denied", the status the wrappers around these commands
     * already know how to read.
     */
    public const int EX_NOPERM = 77;

    /**
     * Commands whose callers asked for a status of their own. A list rather than a global setting,
     * so that the two reporting commands can be told apart from the rest of the application.
     *
     * @var list<string>
     */
    private const array COMMANDS = [
        'app:report:generate',
        'app:audit:run',
    ];

    public function __invoke(ConsoleErrorEvent $event): void
    {
        // Only a refusal of this component. A command that failed for any other reason keeps
        // whatever status it was going to report.
        if (!$event->getError() instanceof AccessDeniedExceptionInterface) {
            return;
        }

        if (\in_array($event->getCommand()?->getName(), self::COMMANDS, true)) {
            $event->setExitCode(self::EX_NOPERM);
        }
    }
}
