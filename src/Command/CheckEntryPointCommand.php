<?php

declare(strict_types=1);

namespace App\Command;

use AccessControl\Attribute\AccessPolicy;
use App\Security\EntryPointVoter;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * The console half of the access environment.
 *
 * The attribute is the one /policies/entry-point carries, and so is the voter — what differs is who
 * filled the environment. There the listener put an HTTP request in it; here the console listener
 * puts this command, its input and its output. One attribute, two circumstances, and no caller had
 * to say which it was.
 *
 * No --as option either: this command needs no identity at all, the entry point itself being the
 * credential. That is what makes it a different question from the guarded commands next to it.
 */
#[AsCommand(name: 'app:entry-point:check', description: 'Decides on the circumstances of the call rather than on who is making it')]
#[AccessPolicy(EntryPointVoter::ATTRIBUTE, message: 'This command is reachable from a console only.')]
final class CheckEntryPointCommand extends Command
{
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $io->success(\sprintf('Granted on "%s".', EntryPointVoter::ATTRIBUTE));
        $io->writeln(' The console listener filled the access environment with this command, its input and its output,');
        $io->writeln(' and EntryPointVoter granted on finding a command there — no requester was involved.');

        return self::SUCCESS;
    }
}
