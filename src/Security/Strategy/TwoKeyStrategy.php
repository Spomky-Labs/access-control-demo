<?php

declare(strict_types=1);

namespace App\Security\Strategy;

use AccessControl\AccessDecision;
use AccessControl\AccessRequest;
use AccessControl\CastVote;
use AccessControl\DecisionVote;
use AccessControl\Strategy\StrategyInterface;

/**
 * A combining algorithm of the application's own: the two-key rule.
 *
 * None of the four Symfony ships says what a launch console says — that one grant is not enough,
 * and that two independent keys have to be turned at once. permit_overrides opens on the first
 * grant, deny_overrides only counts refusals, majority weighs the two sides against each other,
 * and first_applicable stops at whoever speaks first.
 *
 * Implementing StrategyInterface and nothing else is what it takes: `access_control.strategy` is an
 * autoconfigured tag, so this class is a strategy from the moment it exists in src/. It can then be
 * named wherever the shipped ones are — `strategy:` on an #[AccessPolicy], the third argument of
 * AccessControlManager::decide(), or `access_control.default_strategy`.
 *
 * A refusal still wins outright. A quorum rule that let two grants outvote a veto would be a
 * majority rule wearing another name, and the veto is the reason a second key is asked for.
 */
final readonly class TwoKeyStrategy implements StrategyInterface
{
    public function __construct(
        private int $required = 2,
    ) {
    }

    public function getName(): string
    {
        return 'two_keys';
    }

    /**
     * A CastVote is the outcome plus the voter that reached it — the strategy needs only the
     * former, but keeping the pair is what lets the profiler name who said what.
     *
     * @param iterable<CastVote> $votes
     */
    public function evaluate(AccessRequest $accessRequest, iterable $votes): AccessDecision
    {
        $grants = 0;
        $denials = 0;

        foreach ($votes as $vote) {
            match ($vote->outcome->decision) {
                DecisionVote::ACCESS_GRANTED => ++$grants,
                DecisionVote::ACCESS_DENIED => ++$denials,
                DecisionVote::ACCESS_ABSTAIN => null,
            };
        }

        if ($denials > 0) {
            return AccessDecision::deny($accessRequest, $votes, 'A key was refused, and a refusal is not outvoted.');
        }

        if ($grants >= $this->required) {
            return AccessDecision::grant($accessRequest, $votes, \sprintf('%d keys were turned, %d being required.', $grants, $this->required));
        }

        // Told apart from a refusal on purpose: nobody objected, there simply was not a quorum.
        // The manager settles it according to the request's allowIfAllAbstain when nothing was said
        // at all, which is not the same thing as one key short.
        if (0 === $grants) {
            return AccessDecision::abstain($accessRequest, $votes, 'No voter had anything to say.');
        }

        return AccessDecision::deny($accessRequest, $votes, \sprintf('Only %d of the %d required keys were turned.', $grants, $this->required));
    }
}
