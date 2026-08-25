<?php

declare(strict_types=1);

namespace App\Tests;

use AccessControl\Bundle\Test\AccessControlAssertionsTrait;
use AccessControl\DecisionVote;
use App\Security\ComplianceVoter;
use App\Security\DocumentVoter;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Console\Tester\ApplicationTester;
use Symfony\Component\ExpressionLanguage\Expression;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * Asserting on the decision rather than on the status code.
 *
 * A refusal reaches a requester as a bare 403, on purpose — an error page that named the attribute
 * and the voter would be telling an attacker how the lock works. That leaves a test with a number
 * and nothing else, which is why the bundle ships these: they read the decisions the request
 * actually made, so a test can state *which* attribute was refused and by *whom*.
 *
 * They read `access_control.decision_logger`, which the bundle registers in debug mode. That is
 * also why they belong to the bundle rather than to the component: the component's own
 * AccessOutcomeAssertionsTrait works on an answer already in hand, with no container involved.
 */
final class AccessAssertionsTest extends WebTestCase
{
    use AccessControlAssertionsTrait;

    /**
     * A 403 says a request was refused. It does not say what was asked, and the two are not the
     * same thing: a page carrying three policies has three ways to answer 403.
     */
    public function testARefusalCanBeNamedRatherThanCounted(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);

        $client->request('GET', '/documents/1');
        self::assertResponseStatusCodeSame(403);

        // The class-level policy passed and the method-level one did not, which the status code
        // could never have told apart.
        self::assertAccessWasGrantedOn('ROLE_USER');
        self::assertAccessWasDeniedOn('VIEW');
    }

    /**
     * Which voter refused, rather than which attribute — the useful question when several answer
     * the same one.
     */
    public function testTheVoterBehindARefusalCanBeNamed(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);

        // #3 is locked, and /publish-strict reads PUBLISH under deny_overrides. DocumentVoter
        // grants it (an administrator), so the refusal is somebody else's.
        $client->request('GET', '/documents/3/publish-strict');
        self::assertResponseStatusCodeSame(403);

        self::assertAccessWasDeniedOn('PUBLISH');
        self::assertAccessWasDeniedBy(ComplianceVoter::class);
    }

    /**
     * The same page under permit_overrides: the same voters, the same votes, and the compliance
     * refusal no longer carries the decision.
     */
    public function testAVoterCanRefuseWithoutTheRequestBeingRefused(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);

        $client->request('GET', '/documents/3/publish');
        self::assertResponseIsSuccessful();

        // The veto was cast and lost, which is a different thing from not having been cast.
        self::assertAccessWasDeniedBy(ComplianceVoter::class);
        self::assertAccessWasNotDeniedOn('PUBLISH');
    }

    /**
     * An expression is an attribute too, and its is_granted() calls are decisions of their own —
     * so the count is about how many questions were put, not how many pages were guarded.
     */
    public function testDecisionsAreCountedIncludingTheNestedOnes(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);

        $client->request('GET', '/admin/reports');
        self::assertResponseIsSuccessful();

        // ROLE_ADMIN from the class policy, the expression itself, and the IS_AUTHENTICATED_FULLY
        // the expression asked for.
        self::assertAccessDecisionCount(3);
        self::assertAccessWasGrantedOn('ROLE_ADMIN');
        self::assertAccessWasGrantedOn('IS_AUTHENTICATED_FULLY');
    }

    /**
     * An attribute that is not a string cannot be asserted on by value.
     *
     * AccessDecisionEvents::getDecisionsOn() matches with ===, so an Expression is only found by
     * the very instance the attribute was built from — which a test never holds, the attribute
     * living in a controller\'s metadata. Identity is the safe rule for scalars; for objects it
     * means the trait answers on strings and nothing else.
     *
     * The decision is in the log all the same, so the expression is looked up by its own text.
     */
    public function testAnExpressionIsFoundByItsTextRatherThanByValue(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'user', ['ROLE_USER']);

        $client->request('GET', '/documents/1/manage');
        self::assertResponseStatusCodeSame(403);

        // What the trait can still say about this request: the expression asked ROLE_ADMIN of its
        // own accord, and that half is a string.
        self::assertAccessWasDeniedOn('ROLE_ADMIN');
        self::assertAccessWasGrantedOn('IS_AUTHENTICATED_FULLY');

        // And the expression itself, read off the log by what it says.
        $expression = "is_fully_authenticated() and (is_granted('ROLE_ADMIN') or (subject.owner == user.getUserIdentifier() and 'ROLE_MANAGER' in role_names))";

        $matching = array_filter(
            self::getAccessDecisionEvents()->getDecisions(),
            static fn ($event): bool => $event->accessRequest->attribute instanceof Expression
                && $expression === (string) $event->accessRequest->attribute,
        );

        self::assertCount(1, $matching);
        self::assertSame(DecisionVote::ACCESS_DENIED, reset($matching)->accessDecision->decision);
    }

    /**
     * The trail is per request: the second one does not inherit the first's decisions.
     */
    public function testEachRequestHasItsOwnTrail(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'user', ['ROLE_USER']);

        $client->request('GET', '/documents/1');
        self::assertAccessWasGrantedOn('VIEW');

        $client->request('GET', '/dashboard');
        self::assertAccessWasNotDeniedOn('VIEW');
        self::assertAccessDecisionCount(1, 'the dashboard asks one question and inherits none');
    }

    /**
     * The console goes through the same logger, so a guarded command is assertable the same way.
     */
    public function testACommandsDecisionsAreAssertableToo(): void
    {
        // bootKernel() rather than createKernel(): the assertions read the logger off
        // static::getContainer(), which is the booted kernel's — not a second one built alongside.
        $application = new Application(static::bootKernel());
        $application->setAutoExit(false);
        $tester = new ApplicationTester($application);

        $tester->run(['command' => 'app:report:generate', '--as' => 'user']);

        self::assertAccessWasDeniedOn('ROLE_ADMIN');
    }

    /**
     * The two traits answer two different questions, and this is the seam between them: the bundle
     * reads what an elapsed request decided, the component asserts on an answer in hand.
     */
    public function testTheDocumentVoterIsTheOneThatRefusedAView(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);

        $client->request('GET', '/documents/3');
        self::assertResponseStatusCodeSame(403);

        self::assertAccessWasDeniedBy(DocumentVoter::class);
    }

    /**
     * @param list<string> $roles
     */
    private function loginAs(KernelBrowser $client, string $username, array $roles): void
    {
        $client->loginUser(new InMemoryUser($username, $username, $roles));
    }
}
