<?php

declare(strict_types=1);

namespace App\Command;

use AccessControl\Attribute\AccessPolicy;
use AccessControl\Attribute\When;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\ExpressionLanguage\Expression;

/**
 * A conditional policy: the ROLE_ADMIN requirement only applies when --force is passed.
 * The When condition reads the console input from the environment the listener hands over.
 *
 * Try:
 *   bin/console app:document:purge --as=user            # dry-run, allowed for anyone
 *   bin/console app:document:purge --force --as=user    # denied (exit code 113)
 *   bin/console app:document:purge --force --as=admin   # granted
 */
#[AsCommand(name: 'app:document:purge', description: 'Purge documents; --force requires an administrator.')]
#[When(new Expression('input.getOption("force")'), [new AccessPolicy('ROLE_ADMIN', message: 'Only administrators can force-purge documents.')])]
final class PurgeDocumentsCommand extends Command
{
    protected function configure(): void
    {
        $this->addOption('as', null, InputOption::VALUE_REQUIRED, 'Console identity: user, manager or admin');
        $this->addOption('force', null, InputOption::VALUE_NONE, 'Actually purge (guarded by ROLE_ADMIN).');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        if ($input->getOption('force')) {
            $io->success('Documents purged.');
        } else {
            $io->note('Dry-run — pass --force to purge (requires an administrator).');
        }

        return self::SUCCESS;
    }
}
