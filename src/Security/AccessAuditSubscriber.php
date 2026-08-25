<?php

declare(strict_types=1);

namespace App\Security;

use AccessControl\DecisionVote;
use AccessControl\Event\AccessDecisionEvent;
use AccessControl\Event\AccessQueryEvent;
use AccessControl\Event\VoteEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Contracts\Service\ResetInterface;

/**
 * An audit trail of what the component decided, built from the three events it dispatches.
 *
 * The bundle keeps one of these in debug mode, behind `access_control.decision_logger`, and the
 * profiler panel and the test assertions read it. This is the application's own: an audit trail is
 * something a real app keeps in production, where the debug one is not there.
 *
 * The three events answer three different questions:
 *
 *   * VoteEvent — what one voter said, before any strategy combined anything;
 *   * AccessDecisionEvent — what the manager settled on, and under which strategy;
 *   * AccessQueryEvent — that somebody asked at all, dispatched by the entry points and by the
 *     bridge, which is how a question put through Security's checker is still counted here.
 *
 * A decision made while another one is being made is a *child* of it — an expression calling
 * is_granted() is the usual case — and the event carries that parentage, so the trail below is a
 * tree flattened rather than a list of unrelated answers.
 */
final class AccessAuditSubscriber implements EventSubscriberInterface, ResetInterface
{
    /**
     * @var list<array{attribute: string, decision: string, strategy: string|null, reason: string|null, nested: bool}>
     */
    private array $decisions = [];

    /**
     * @var list<array{voter: string, decision: string, reason: string|null}>
     */
    private array $votes = [];

    private int $queries = 0;

    public static function getSubscribedEvents(): array
    {
        return [
            AccessDecisionEvent::class => 'onDecision',
            VoteEvent::class => 'onVote',
            AccessQueryEvent::class => 'onQuery',
        ];
    }

    public function onDecision(AccessDecisionEvent $event): void
    {
        $this->decisions[] = [
            'attribute' => $this->label($event->accessRequest->attribute),
            'decision' => $event->accessDecision->decision->value,
            'strategy' => $event->strategy,
            'reason' => $event->accessDecision->reason,
            // A question a voter asked while answering another one.
            'nested' => null !== $event->parent,
        ];
    }

    public function onVote(VoteEvent $event): void
    {
        // Abstentions are the common case and say nothing; keeping them would bury the trail.
        if (DecisionVote::ACCESS_ABSTAIN === $event->voterOutcome->decision) {
            return;
        }

        $this->votes[] = [
            'voter' => (new \ReflectionClass($event->voter))->getShortName(),
            'decision' => $event->voterOutcome->decision->value,
            'reason' => $event->voterOutcome->reason,
        ];
    }

    public function onQuery(AccessQueryEvent $event): void
    {
        ++$this->queries;
    }

    /**
     * @return list<array{attribute: string, decision: string, strategy: string|null, reason: string|null, nested: bool}>
     */
    public function getDecisions(): array
    {
        return $this->decisions;
    }

    /**
     * @return list<array{voter: string, decision: string, reason: string|null}>
     */
    public function getVotes(): array
    {
        return $this->votes;
    }

    public function getQueryCount(): int
    {
        return $this->queries;
    }

    /**
     * @return list<array{attribute: string, decision: string, strategy: string|null, reason: string|null, nested: bool}>
     */
    public function getRefusals(): array
    {
        return array_values(array_filter(
            $this->decisions,
            static fn (array $decision): bool => DecisionVote::ACCESS_DENIED->value === $decision['decision'],
        ));
    }

    /**
     * A long-running worker would otherwise carry one request's trail into the next.
     */
    public function reset(): void
    {
        $this->decisions = [];
        $this->votes = [];
        $this->queries = 0;
    }

    /**
     * An attribute is not always a string: an Expression and a Closure are attributes too.
     */
    private function label(mixed $attribute): string
    {
        return match (true) {
            \is_string($attribute) => $attribute,
            $attribute instanceof \Stringable => (string) $attribute,
            default => get_debug_type($attribute),
        };
    }
}
