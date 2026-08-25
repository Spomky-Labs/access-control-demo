<?php

declare(strict_types=1);

namespace App\Command;

use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\AtLeastOneOf;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * A composite policy: either ROLE_ADMIN or ROLE_MANAGER is enough to run the audit.
 *
 * Try:
 *   bin/console app:audit:run --as=manager   # granted
 *   bin/console app:audit:run --as=admin     # granted
 *   bin/console app:audit:run --as=user      # denied (exit code 113)
 */
#[AsCommand(name: 'app:audit:run', description: 'Run an audit (managers or administrators).')]
#[AtLeastOneOf([new AccessPolicy('ROLE_ADMIN'), new AccessPolicy('ROLE_MANAGER')], message: 'Managers or administrators only.')]
final class RunAuditCommand extends Command
{
    protected function configure(): void
    {
        $this->addOption('as', null, InputOption::VALUE_REQUIRED, 'Console identity: user, manager or admin');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $io->success('Audit completed.');

        return self::SUCCESS;
    }
}
