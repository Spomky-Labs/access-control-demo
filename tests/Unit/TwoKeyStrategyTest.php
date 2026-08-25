<?php

declare(strict_types=1);

namespace App\Tests\Unit;

use AccessControl\AccessRequest;
use AccessControl\DecisionVote;
use AccessControl\Test\AccessDecisionStrategyTestTrait;
use App\Security\Strategy\TwoKeyStrategy;
use PHPUnit\Framework\TestCase;

/**
 * The application's own combining algorithm, run through the matrix the component ships for it.
 *
 * AccessDecisionStrategyTestTrait is a trait rather than a base class deliberately: a strategy test
 * usually has a base case of its own already, and would otherwise have to choose between the two.
 * provideStrategyTests() is the only thing to write — getVoters() builds the votes, and testDecide()
 * assembles a manager around the strategy and puts one request to it.
 *
 * Its expectation is a boolean, because a manager settles an abstention rather than handing it
 * back. The one case that needs telling apart — a quorum one key short, against nobody having
 * anything to say — is put to evaluate() directly at the bottom.
 */
final class TwoKeyStrategyTest extends TestCase
{
    use AccessDecisionStrategyTestTrait;

    public static function provideStrategyTests(): iterable
    {
        $strategy = new TwoKeyStrategy();

        // Two keys and no objection: the only shape that opens.
        yield 'two grants' => [$strategy, self::getVoters(2, 0, 0), true];
        yield 'three grants' => [$strategy, self::getVoters(3, 0, 0), true];
        yield 'two grants among abstentions' => [$strategy, self::getVoters(2, 0, 5), true];

        // One key short. permit_overrides would have opened on the first of these.
        yield 'one grant' => [$strategy, self::getVoters(1, 0, 0), false];
        yield 'one grant among abstentions' => [$strategy, self::getVoters(1, 0, 3), false];

        // A refusal is not outvoted, which is the whole reason a second key is asked for.
        // majority would have granted the first of these, two weighing more than one.
        yield 'two grants against one denial' => [$strategy, self::getVoters(2, 1, 0), false];
        yield 'five grants against one denial' => [$strategy, self::getVoters(5, 1, 0), false];

        // Nobody said anything: settled by allowIfAllAbstain, which defaults to refusing.
        yield 'all abstain' => [$strategy, self::getVoters(0, 0, 3), false];
        yield 'no voter at all' => [$strategy, [], false];
    }

    /**
     * A quorum threshold other than two, since the rule is a threshold and not the number two.
     */
    public function testTheThresholdIsWhateverItWasBuiltWith(): void
    {
        $strategy = new TwoKeyStrategy(required: 3);
        $request = new AccessRequest(null, 'ROLE_FOO');

        $twoKeys = $strategy->evaluate($request, [self::getCastVote(DecisionVote::ACCESS_GRANTED), self::getCastVote(DecisionVote::ACCESS_GRANTED)]);
        self::assertSame(DecisionVote::ACCESS_DENIED, $twoKeys->decision);

        $threeKeys = $strategy->evaluate($request, [
            self::getCastVote(DecisionVote::ACCESS_GRANTED),
            self::getCastVote(DecisionVote::ACCESS_GRANTED),
            self::getCastVote(DecisionVote::ACCESS_GRANTED),
        ]);
        self::assertSame(DecisionVote::ACCESS_GRANTED, $threeKeys->decision);
    }

    /**
     * Silence and a short quorum both come out of the manager as a refusal, and are not the same
     * thing: only the second is an objection. evaluate() is where the difference is still visible.
     */
    public function testSilenceAndAShortQuorumAreDifferentAnswers(): void
    {
        $strategy = new TwoKeyStrategy();
        $request = new AccessRequest(null, 'ROLE_FOO');

        $silence = $strategy->evaluate($request, [self::getCastVote(DecisionVote::ACCESS_ABSTAIN)]);
        self::assertSame(DecisionVote::ACCESS_ABSTAIN, $silence->decision, 'left for the manager to settle');

        $short = $strategy->evaluate($request, [self::getCastVote(DecisionVote::ACCESS_GRANTED)]);
        self::assertSame(DecisionVote::ACCESS_DENIED, $short->decision);
        self::assertStringContainsString('Only 1 of the 2 required keys', (string) $short->reason);
    }

    public function testItAnswersToTheNameItIsAskedFor(): void
    {
        self::assertSame('two_keys', (new TwoKeyStrategy())->getName());
    }
}
