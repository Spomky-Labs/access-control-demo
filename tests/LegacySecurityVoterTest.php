<?php

declare(strict_types=1);

namespace App\Tests;

use AccessControl\Bridge\Security\VoterAdapter;
use AccessControl\Bundle\Test\AccessControlAssertionsTrait;
use AccessControl\DecisionVote;
use App\Repository\DocumentStore;
use App\Security\LegacyAuditVoter;
use App\Service\AccessInspector;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * A Security voter, untouched, deciding for the AccessControl component.
 *
 * This is the migration path and the reason the bridge exists at all: an application arrives with a
 * dozen `security.voter` services and cannot rewrite them in the commit that installs the bundle.
 * Each one is wrapped in a VoterAdapter and handed to the component, where it votes beside the
 * component's own and is combined by the same strategy.
 */
final class LegacySecurityVoterTest extends WebTestCase
{
    use AccessControlAssertionsTrait;

    public function testASecurityVoterIsConsultedByTheComponent(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);
        $client->request('GET', '/dashboard');

        $inspector = static::getContainer()->get(AccessInspector::class);
        $store = static::getContainer()->get(DocumentStore::class);

        // #1 is locked, #2 is not. Nothing but the Security voter claims AUDIT, so both answers
        // are its own — reached through the component's manager.
        self::assertTrue($inspector->isGranted(LegacyAuditVoter::AUDIT, $store->find(1)));
        self::assertFalse($inspector->isGranted(LegacyAuditVoter::AUDIT, $store->find(2)));
    }

    public function testItStillAnswersToItsOwnRules(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'user', ['ROLE_USER']);
        $client->request('GET', '/dashboard');

        $inspector = static::getContainer()->get(AccessInspector::class);
        $store = static::getContainer()->get(DocumentStore::class);

        // Locked, but a plain user is not a manager.
        self::assertFalse($inspector->isGranted(LegacyAuditVoter::AUDIT, $store->find(1)));
    }

    /**
     * How a bridged voter shows up in the decision log — and it is the adapter, not the class the
     * application wrote.
     *
     * assertAccessWasDeniedBy() filters the votes on `$event->voter instanceof $voter`, and the
     * voter on the event is the VoterAdapter. The adapter keeps the wrapped voter on a public
     * property precisely so it can be named, and the profiler panel does read it, so the two
     * disagree: the panel says LegacyAuditVoter and this assertion cannot.
     *
     * Pinned as it stands rather than worked around. If the constraint learns to look through the
     * adapter, this test is where that shows up.
     */
    public function testABridgedVoterAppearsInTheTrailAsItsAdapter(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'user', ['ROLE_USER']);
        $client->request('GET', '/dashboard');

        $store = static::getContainer()->get(DocumentStore::class);
        static::getContainer()->get(AccessInspector::class)->isGranted(LegacyAuditVoter::AUDIT, $store->find(1));

        self::assertAccessWasDeniedOn(LegacyAuditVoter::AUDIT);
        self::assertAccessWasDeniedBy(VoterAdapter::class);

        // The application's own class is one hop away, on the adapter's public property.
        $votes = self::getAccessDecisionEvents()->getVotesBy(VoterAdapter::class, DecisionVote::ACCESS_DENIED);
        self::assertNotEmpty($votes);
        self::assertInstanceOf(LegacyAuditVoter::class, $votes[0]->voter->voter);

        // And the reason it wrote reaches the trail unchanged, through Security's Vote object.
        self::assertStringContainsString('takes a manager', (string) $votes[0]->voterOutcome->reason);
    }

    /**
     * Reached the other way round as well: Security's own checker now goes through the component,
     * so the same voter answers whichever door the question comes in by.
     */
    public function testTheSameVoterAnswersThroughSecurityAsWell(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);
        $client->request('GET', '/dashboard');

        $security = static::getContainer()->get('security.authorization_checker');
        $store = static::getContainer()->get(DocumentStore::class);

        self::assertTrue($security->isGranted(LegacyAuditVoter::AUDIT, $store->find(1)));
        self::assertFalse($security->isGranted(LegacyAuditVoter::AUDIT, $store->find(2)));
    }

    /**
     * It is a Security voter and not a component one, which is the whole premise: the file did not
     * change when the bundle was registered.
     */
    public function testItIsReallyASecurityVoter(): void
    {
        self::assertTrue(is_subclass_of(LegacyAuditVoter::class, \Symfony\Component\Security\Core\Authorization\Voter\VoterInterface::class));
        self::assertFalse(is_subclass_of(LegacyAuditVoter::class, \AccessControl\VoterInterface::class));
    }

    /**
     * @param list<string> $roles
     */
    private function loginAs(KernelBrowser $client, string $username, array $roles): void
    {
        $client->loginUser(new InMemoryUser($username, $username, $roles));
    }
}
