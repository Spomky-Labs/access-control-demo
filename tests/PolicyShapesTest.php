<?php

declare(strict_types=1);

namespace App\Tests;

use AccessControl\DecisionVote;
use App\Controller\PolicyController;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Clock\Test\ClockSensitiveTrait;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The shapes of a policy beyond the plain #[AccessPolicy]: a composite of the application's own,
 * the All composite, and what a manager makes of everybody abstaining.
 */
final class PolicyShapesTest extends WebTestCase
{
    use ClockSensitiveTrait;

    public function testTheIndexIsPublic(): void
    {
        $client = static::createClient();
        $client->request('GET', '/policies');

        self::assertResponseIsSuccessful();
    }

    /**
     * The window refuses before it looks at the nested policy, so it refuses everyone — which is
     * exactly what tells it apart from #[When], where a failing condition abstains and lets
     * something else grant.
     */
    public function testACustomCompositeRefusesOutsideItsWindow(): void
    {
        static::mockTime('2026-08-04 22:30:00');

        $client = static::createClient();

        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);
        $client->request('GET', '/policies/business-hours');
        self::assertResponseStatusCodeSame(403, 'a manager is turned away at 22:30');

        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);
        $client->request('GET', '/policies/business-hours');
        self::assertResponseStatusCodeSame(403, 'and so is an administrator: the window is not about who asks');
    }

    public function testTheSameCompositeAppliesItsNestedPolicyInsideTheWindow(): void
    {
        static::mockTime('2026-08-04 10:30:00');

        $client = static::createClient();

        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);
        $client->request('GET', '/policies/business-hours');
        self::assertResponseIsSuccessful();

        // Inside the window the nested policy is what decides, and a plain user does not pass it.
        $this->loginAs($client, 'user', ['ROLE_USER']);
        $client->request('GET', '/policies/business-hours');
        self::assertResponseStatusCodeSame(403);
    }

    /**
     * The boundary is closed at the bottom and open at the top, as the attribute declares.
     */
    public function testTheWindowBoundariesAreWhereTheyWereDeclared(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);

        static::mockTime('2026-08-04 09:00:00');
        $client->request('GET', '/policies/business-hours');
        self::assertResponseIsSuccessful('9:00 is inside');

        static::mockTime('2026-08-04 18:00:00');
        $client->request('GET', '/policies/business-hours');
        self::assertResponseStatusCodeSame(403, '18:00 is not');
    }

    /**
     * All wants both halves, and neither of these implies the other.
     */
    public function testAllDemandsEveryNestedPolicy(): void
    {
        $client = static::createClient();

        // The owner of #2 is a manager: both halves hold.
        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);
        $client->request('GET', '/policies/both/2');
        self::assertResponseIsSuccessful();

        // An admin reaches ROLE_MANAGER through the hierarchy and still does not own #2, so EDIT
        // refuses and All hands that refusal back.
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);
        $client->request('GET', '/policies/both/2');
        self::assertResponseStatusCodeSame(403);

        // The owner of #1 passes EDIT and holds no ROLE_MANAGER, so the other half refuses.
        $this->loginAs($client, 'user', ['ROLE_USER']);
        $client->request('GET', '/policies/both/1');
        self::assertResponseStatusCodeSame(403);
    }

    /**
     * The same two policies under AtLeastOneOf let either half through, which is the contrast the
     * page points at.
     */
    public function testAtLeastOneOfIsTheOtherReadingOfTheSamePair(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);

        $client->request('GET', '/playground/either');
        self::assertResponseIsSuccessful();
    }

    /**
     * Nobody claims the attribute, so the manager settles it — and the policy says how, for its own
     * request, overriding the application-wide default.
     */
    public function testAPolicyDecidesWhatSilenceMeansForItsOwnRequest(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'user', ['ROLE_USER']);

        // allowIfAllAbstain: true — the page renders.
        $crawler = $client->request('GET', '/policies/abstain');
        self::assertResponseIsSuccessful();

        $rows = $crawler->filter('tbody tr');
        self::assertStringContainsString('ACCESS_GRANTED', $rows->eq(0)->text());
        self::assertStringContainsString('ACCESS_DENIED', $rows->eq(1)->text());

        // The same attribute with the default left alone: this application refuses.
        $client->request('GET', '/policies/abstain-strict');
        self::assertResponseStatusCodeSame(403);
    }

    public function testTheUnclaimedAttributeIsReallyUnclaimed(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);
        $client->request('GET', '/dashboard');

        $decision = static::getContainer()->get(\App\Service\AccessInspector::class)
            ->decide(PolicyController::UNCLAIMED);

        // Whoever was asked had nothing to say: an abstention here is silence, not disagreement.
        // Some voters are asked at all — a Security voter bridged through VoterAdapter supports
        // every attribute unless it implements CacheableVoterInterface and says otherwise — and
        // being asked is not the same as answering.
        foreach ($decision->votes as $vote) {
            self::assertSame(
                DecisionVote::ACCESS_ABSTAIN,
                $vote->outcome->decision,
                \sprintf('%s had an opinion on an attribute nobody claims.', $vote->voter::class),
            );
        }
    }

    /**
     * @param list<string> $roles
     */
    private function loginAs(KernelBrowser $client, string $username, array $roles): void
    {
        $client->loginUser(new InMemoryUser($username, $username, $roles));
    }
}
