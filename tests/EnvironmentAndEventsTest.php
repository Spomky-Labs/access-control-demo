<?php

declare(strict_types=1);

namespace App\Tests;

use App\Security\AccessAuditSubscriber;
use App\Security\EntryPointVoter;
use App\Service\AccessInspector;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\ApplicationTester;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The access environment, and the events the component dispatches.
 *
 * The environment is the fourth category of the ABAC vocabulary — the circumstances of a call —
 * and what makes it worth having is that no caller fills it: each entry point puts in what it alone
 * knows, so one attribute means "over HTTP" in one place and "on this console" in another.
 */
final class EnvironmentAndEventsTest extends WebTestCase
{
    public function testTheWebEntryPointFillsTheEnvironmentWithTheRequest(): void
    {
        $client = static::createClient();

        $crawler = $client->request('GET', '/policies/entry-point');
        self::assertResponseIsSuccessful('the test client comes from the loopback address');

        // The voter's own words, read back off the audit trail: the listener's request and the
        // key the *policy* added, merged, both reaching the voter and nobody else.
        $reason = $crawler->filter('#granted-reason')->text();
        self::assertStringContainsString('over HTTP', $reason);
        self::assertStringContainsString('"policies" area', $reason);
    }

    public function testTheSameVoterAbstainsWhenNoEntryPointFilledAnything(): void
    {
        $client = static::createClient();
        $client->request('GET', '/policies/entry-point');

        // Asked programmatically inside the very same request: nothing to read, so nothing to say.
        $decision = static::getContainer()->get(AccessInspector::class)->decide(EntryPointVoter::ATTRIBUTE);

        self::assertFalse($decision->isGranted(), 'an abstention is settled by the manager, and this app refuses');
        self::assertStringContainsString('No entry point filled', (string) $decision->reason);
    }

    public function testAnUntrustedOriginIsRefusedOverHttp(): void
    {
        $client = static::createClient();

        // Signed in, so the refusal comes out as a 403 rather than as a trip to the login form —
        // the origin is what is being refused, not the identity.
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);

        $client->request('GET', '/policies/entry-point', server: ['REMOTE_ADDR' => '203.0.113.7']);
        self::assertResponseStatusCodeSame(403, 'holding every role changes nothing: the call came from elsewhere');
    }

    /**
     * The console fills the environment with the command rather than a request, and the very same
     * attribute is granted for a different reason — without any requester at all.
     */
    public function testTheConsoleEntryPointFillsTheEnvironmentWithTheCommand(): void
    {
        $application = new Application(static::createKernel());
        $application->setAutoExit(false);
        $tester = new ApplicationTester($application);

        self::assertSame(Command::SUCCESS, $tester->run(['command' => 'app:entry-point:check']));
        self::assertStringContainsString('Granted', $tester->getDisplay());
    }

    /**
     * The three events, read by the application's own subscriber rather than by the bundle's debug
     * logger — which is what a production audit trail would have to do.
     */
    public function testTheAuditTrailRecordsDecisionsVotesAndQueries(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);

        $crawler = $client->request('GET', '/policies/audit');
        self::assertResponseIsSuccessful();

        $audit = static::getContainer()->get(AccessAuditSubscriber::class);

        self::assertNotEmpty($audit->getDecisions(), 'the page is guarded, so at least one decision was settled');
        self::assertGreaterThan(0, $audit->getQueryCount(), 'an entry point asked');

        $attributes = array_column($audit->getDecisions(), 'attribute');
        self::assertContains('ROLE_USER', $attributes, 'the policy guarding the page');
        self::assertContains('ROLE_ADMIN', $attributes, 'asked in the controller, and refused');

        // The refusal is in the trail as such, and did not stop the page from rendering: a
        // programmatic question is not a guard.
        self::assertNotEmpty($audit->getRefusals());

        // ROLE_MANAGER is only ever asked from inside the expression, so its decision is a child.
        $nested = array_filter($audit->getDecisions(), static fn (array $d): bool => $d['nested']);
        self::assertNotEmpty($nested, 'is_granted() inside an expression is a decision of its own');

        self::assertStringContainsString('Decisions', $crawler->filter('h2')->eq(0)->text());
    }

    /**
     * A vote is recorded before any strategy has combined anything, so the trail can say who said
     * what and not only what came out.
     */
    public function testVotesAreRecordedWithTheVoterThatCastThem(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'user', ['ROLE_USER']);

        $crawler = $client->request('GET', '/policies/audit');
        self::assertResponseIsSuccessful();

        $voters = [];
        foreach ($crawler->filter('table')->eq(1)->filter('tbody tr') as $node) {
            $cells = (new Crawler($node))->filter('td')->each(static fn ($td) => trim($td->text()));
            $voters[] = $cells[0];
        }

        self::assertContains('RoleVoter', $voters, 'the role checks went through the RoleVoter');
    }

    public function testTheTrailIsEmptiedBetweenRequests(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'user', ['ROLE_USER']);

        $client->request('GET', '/policies/audit');
        $first = \count(static::getContainer()->get(AccessAuditSubscriber::class)->getDecisions());

        $client->request('GET', '/policies/audit');
        $second = \count(static::getContainer()->get(AccessAuditSubscriber::class)->getDecisions());

        // kernel.reset runs between requests, so the second page did not inherit the first's trail.
        self::assertSame($first, $second);
    }

    /**
     * @param list<string> $roles
     */
    private function loginAs(KernelBrowser $client, string $username, array $roles): void
    {
        $client->loginUser(new InMemoryUser($username, $username, $roles));
    }
}
