<?php

declare(strict_types=1);

namespace App\Command;

use AccessControl\Attribute\AccessPolicy;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * A class-level policy guards the whole command: the AccessControl console listener
 * evaluates ROLE_ADMIN against the console requester before execute() runs.
 *
 * Try:
 *   bin/console app:report:generate --as=admin      # granted
 *   bin/console app:report:generate --as=user       # denied (exit code 113)
 *   bin/console app:report:generate --as=admin --profile -v   # + profiler link
 */
#[AsCommand(name: 'app:report:generate', description: 'Generate a report (administrators only).')]
#[AccessPolicy('ROLE_ADMIN', message: 'Only administrators can generate reports.')]
final class GenerateReportCommand extends Command
{
    protected function configure(): void
    {
        $this->addOption('as', null, InputOption::VALUE_REQUIRED, 'Console identity: user, manager or admin');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $io->success('Report generated.');

        return self::SUCCESS;
    }
}
