<?php

declare(strict_types=1);

namespace App\Command;

use AccessControl\DecisionVote;
use App\Repository\DocumentStore;
use App\Service\AccessInspector;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * A programmatic command: it is NOT guarded by an attribute. Instead it calls the
 * AccessControl service itself and reports the full decision — verdict, reason and the
 * individual votes — which makes it a handy way to inspect why access is (not) granted.
 *
 * Try:
 *   bin/console app:access:check ROLE_ADMIN --as=admin
 *   bin/console app:access:check VIEW 2 --as=user      # denied, with the voter's reason
 *   bin/console app:access:check PUBLISH 1 --as=user   # two voters disagree
 */
#[AsCommand(name: 'app:access:check', description: 'Programmatically check an access decision and show the reasoning.')]
final class CheckAccessCommand extends Command
{
    public function __construct(
        private readonly AccessInspector $inspector,
        private readonly DocumentStore $store,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument('attribute', InputArgument::REQUIRED, 'Attribute to check: ROLE_ADMIN, VIEW, EDIT, PUBLISH, PUBLIC_ACCESS…')
            ->addArgument('document', InputArgument::OPTIONAL, 'Optional document id, used as the subject')
            ->addOption('as', null, InputOption::VALUE_REQUIRED, 'Console identity: user, manager or admin');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $attribute = $input->getArgument('attribute');

        $subject = null;
        if (null !== $id = $input->getArgument('document')) {
            if (null === $subject = $this->store->find((int) $id)) {
                $io->error(\sprintf('Document "%s" does not exist.', $id));

                return self::FAILURE;
            }
        }

        $decision = $this->inspector->decide($attribute, $subject);
        $granted = DecisionVote::ACCESS_GRANTED === $decision->decision;

        $io->section(\sprintf(
            'Attribute "%s"%s',
            \is_string($attribute) ? $attribute : get_debug_type($attribute),
            null !== $subject ? \sprintf(' on document #%d (owner: %s)', $subject->id, $subject->owner) : '',
        ));

        $granted ? $io->success('GRANTED') : $io->warning($decision->decision->value);

        if (null !== $decision->reason) {
            $io->writeln(' Reason: '.$decision->reason);
            $io->newLine();
        }

        // A CastVote pairs an outcome with the voter that reached it, so the table can name who
        // said what rather than only what was said.
        $votes = [];
        foreach ($decision->votes as $vote) {
            $votes[] = [
                (new \ReflectionClass($vote->voter))->getShortName(),
                $vote->outcome->decision->value,
                $vote->outcome->reason ?? '',
            ];
        }
        if ([] !== $votes) {
            $io->table(['Voter', 'Vote', 'Reason'], $votes);
        }

        return self::SUCCESS;
    }
}
