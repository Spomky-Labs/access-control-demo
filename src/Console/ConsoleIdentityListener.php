<?php

declare(strict_types=1);

namespace App\Console;

use Symfony\Component\Console\ConsoleEvents;
use Symfony\Component\Console\Event\ConsoleCommandEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * Nothing fills the security token storage on the console, so a command guarded by a
 * role would always be denied. This listener stands in a "service identity": when a
 * command carries a --as option, it puts a matching token in the storage, which the
 * TokenStorageRequesterProvider then hands to the AccessControl console listener.
 *
 * In a real app this would be a proper service account (an API token, a system user…);
 * here three fixed identities are enough to explore the behaviour.
 */
final class ConsoleIdentityListener implements EventSubscriberInterface
{
    /**
     * @var array<string, list<string>>
     */
    private const array IDENTITIES = [
        'user' => ['ROLE_USER'],
        'manager' => ['ROLE_MANAGER'],
        'admin' => ['ROLE_ADMIN'],
    ];

    public function __construct(
        private readonly TokenStorageInterface $tokenStorage,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        // Above the AccessControl console listener (20) so the requester is in place before any
        // policy is evaluated, below the profiler's initialize (4096) so profiling still wraps it.
        return [ConsoleEvents::COMMAND => ['onCommand', 512]];
    }

    public function onCommand(ConsoleCommandEvent $event): void
    {
        $input = $event->getInput();
        if (!$input->hasOption('as') || null === $identity = $input->getOption('as')) {
            // No identity requested: make sure none lingers from an earlier command in the
            // same process, so the requester is genuinely anonymous (PUBLIC_ACCESS only).
            $this->tokenStorage->setToken(null);

            return;
        }

        if (!isset(self::IDENTITIES[$identity])) {
            throw new \InvalidArgumentException(\sprintf('Unknown identity "%s". Use one of: %s.', $identity, implode(', ', array_keys(self::IDENTITIES))));
        }

        $roles = self::IDENTITIES[$identity];
        $this->tokenStorage->setToken(new UsernamePasswordToken(new InMemoryUser($identity, null, $roles), 'console', $roles));
    }
}
