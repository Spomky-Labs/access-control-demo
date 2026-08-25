<?php

declare(strict_types=1);

namespace App\Security\Handler;

use AccessControl\AccessOutcome;
use AccessControl\AccessPolicyContext;
use AccessControl\AccessPolicyEvaluator;
use AccessControl\Attribute\AccessPolicyInterface;
use AccessControl\DecisionVote;
use AccessControl\Handler\AccessPolicyHandlerInterface;
use App\Security\Attribute\DuringBusinessHours;
use Psr\Clock\ClockInterface;

/**
 * Reads the DuringBusinessHours attribute, which is what turns it from a piece of metadata into a
 * policy the evaluator applies.
 *
 * `access_control.policy_handler` is an autoconfigured tag, so implementing the interface is the
 * whole registration. The evaluator stops at the first handler that claims a policy, which is why
 * supports() must claim this attribute and nothing else: claiming a foreign one takes it away from
 * the handler that could have read it.
 *
 * The clock is injected rather than read out of the environment. An entry point fills the
 * environment with what it alone knows — the request on the web, the command on the console — and
 * the time of day is not that: a policy that abstained on a missing key would fail open, and no
 * caller should be able to disable a window by leaving it out.
 */
final readonly class DuringBusinessHoursHandler implements AccessPolicyHandlerInterface
{
    public function __construct(
        private ClockInterface $clock,
    ) {
    }

    public function supports(AccessPolicyInterface $accessPolicy): bool
    {
        return $accessPolicy instanceof DuringBusinessHours;
    }

    public function handle(AccessPolicyInterface $accessPolicy, AccessPolicyContext $context, AccessPolicyEvaluator $evaluator): AccessOutcome
    {
        \assert($accessPolicy instanceof DuringBusinessHours);

        $hour = (int) $this->clock->now()->format('G');

        // Refused rather than abstained, which is the whole difference from #[When]: a window
        // nobody passes outside of cannot step aside and let another policy grant.
        if ($hour < $accessPolicy->from || $hour >= $accessPolicy->to) {
            return AccessOutcome::deny(\sprintf('It is %d:00, outside the %d:00-%d:00 window.', $hour, $accessPolicy->from, $accessPolicy->to));
        }

        $granted = 0;

        foreach ($accessPolicy->accessPolicies as $nested) {
            $outcome = $evaluator->evaluate($nested, $context);

            if (DecisionVote::ACCESS_DENIED === $outcome->decision) {
                return $outcome;
            }

            if (DecisionVote::ACCESS_GRANTED === $outcome->decision) {
                ++$granted;
            }
        }

        // Inside the window with nothing to say is an abstention, not a grant: the window is a
        // condition on the nested policies and not a policy of its own.
        if (0 === $granted) {
            return AccessOutcome::abstain('Inside the window, but no nested access policy applied.');
        }

        return AccessOutcome::grant('Inside the window, and every nested access policy granted access.');
    }
}
