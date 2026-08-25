<?php

declare(strict_types=1);

namespace App\Tests\Unit;

use AccessControl\AccessPolicyContext;
use AccessControl\Attribute\AccessPolicy;
use AccessControl\Handler\AccessPolicyHandlerInterface;
use AccessControl\Test\AccessOutcomeAssertionsTrait;
use AccessControl\Test\AccessPolicyHandlerTestTrait;
use App\Security\Attribute\DuringBusinessHours;
use App\Security\Handler\DuringBusinessHoursHandler;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * The application's own policy handler, on its own.
 *
 * A composite handler is the extension point that used to be hardest to test: it calls the
 * evaluator back for each of its children, so a test had to assemble a manager and its voters just
 * to make a child grant or refuse — and that assembly ended up being what the test measured.
 * AccessPolicyHandlerTestTrait replaces the children with FixedOutcomeAccessPolicy, so the test
 * says what each child answers and nothing stands between it and the handler.
 *
 * granting(), denying() and abstaining() are the canned children; evaluate() runs the handler
 * against them. The trait also checks, on its own, that the handler claims what it should and
 * leaves alone what it should not — a handler that claims a policy it cannot read takes it away
 * from the one that could, the evaluator stopping at the first that says yes.
 */
final class DuringBusinessHoursHandlerTest extends TestCase
{
    use AccessOutcomeAssertionsTrait;
    use AccessPolicyHandlerTestTrait;

    private string $now = '2026-08-04 10:00:00';

    protected function createHandler(): AccessPolicyHandlerInterface
    {
        return new DuringBusinessHoursHandler(new MockClock($this->now));
    }

    public static function provideSupportedPolicies(): iterable
    {
        yield 'empty' => [new DuringBusinessHours([])];
        yield 'with a nested policy' => [new DuringBusinessHours([new AccessPolicy('ROLE_MANAGER')])];
        yield 'with its own window' => [new DuringBusinessHours([], from: 0, to: 24)];
    }

    /**
     * Outside the window the children are never reached, which is the point of a window: it is not
     * one more opinion to be weighed against theirs.
     */
    public function testItRefusesOutsideTheWindowWhateverTheChildrenSay(): void
    {
        $this->now = '2026-08-04 22:30:00';

        $outcome = $this->evaluate(new DuringBusinessHours([self::granting('A child that would have granted.')]));

        self::assertAccessDenied($outcome);
        self::assertStringContainsString('outside the 9:00-18:00 window', (string) $outcome->reason);
    }

    /**
     * The difference from #[When], stated as an assertion: a failing condition there abstains and
     * lets something else grant, and a closed window has to refuse instead.
     */
    public function testARefusalRatherThanAnAbstentionIsWhatSetsItApartFromWhen(): void
    {
        $this->now = '2026-08-04 03:00:00';

        self::assertAccessDenied($this->evaluate(new DuringBusinessHours([self::granting()])));
    }

    public function testInsideTheWindowTheChildrenDecide(): void
    {
        self::assertAccessGranted($this->evaluate(new DuringBusinessHours([self::granting()])));
        self::assertAccessDenied($this->evaluate(new DuringBusinessHours([self::denying()])));
    }

    /**
     * Every child must grant, and the first refusal is handed back as it stands — so the message a
     * requester sees is the one the failing policy wrote, not a summary of the composite.
     */
    public function testOneRefusingChildRefusesTheWhole(): void
    {
        $outcome = $this->evaluate(new DuringBusinessHours([
            self::granting('The first child agreed.'),
            self::denying('The second child did not.'),
            self::granting('Never reached.'),
        ]));

        self::assertAccessDenied($outcome);
        self::assertSame('The second child did not.', $outcome->reason);
    }

    /**
     * Inside the window with nothing to say is an abstention, not a grant: the window is a
     * condition on the children and not a policy of its own.
     */
    public function testAnEmptyOrSilentCompositeAbstains(): void
    {
        self::assertAccessAbstained($this->evaluate(new DuringBusinessHours([])));
        self::assertAccessAbstained($this->evaluate(new DuringBusinessHours([self::abstaining()])));
    }

    public function testTheWindowIsClosedBelowAndOpenAbove(): void
    {
        $this->now = '2026-08-04 09:00:00';
        self::assertAccessGranted($this->evaluate(new DuringBusinessHours([self::granting()])));

        $this->now = '2026-08-04 17:59:59';
        self::assertAccessGranted($this->evaluate(new DuringBusinessHours([self::granting()])));

        $this->now = '2026-08-04 18:00:00';
        self::assertAccessDenied($this->evaluate(new DuringBusinessHours([self::granting()])));
    }

    public function testAWindowOfItsOwnIsHonoured(): void
    {
        $this->now = '2026-08-04 02:00:00';

        self::assertAccessGranted($this->evaluate(new DuringBusinessHours([self::granting()], from: 0, to: 6)));
        self::assertAccessDenied($this->evaluate(new DuringBusinessHours([self::granting()], from: 6, to: 12)));
    }

    /**
     * The context is handed down untouched, so a child sees the requester and the arguments the
     * composite was given.
     */
    public function testTheContextReachesTheChildren(): void
    {
        $context = new AccessPolicyContext(requester: 'someone', arguments: ['document' => 'a document']);

        self::assertAccessGranted($this->evaluate(new DuringBusinessHours([self::granting()]), $context));
    }
}
