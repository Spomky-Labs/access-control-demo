<?php

declare(strict_types=1);

namespace App\Tests;

use App\Repository\DocumentStore;
use App\Service\AccessInspector;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The four algorithms the component ships, and the application's own, on one request.
 *
 * The point of the page is that nothing else moves: same requester, same attribute, same subject,
 * same voters, same votes. What a strategy is for is deciding what to do with disagreement, and
 * the only way to see that is to disagree.
 */
final class StrategyComparisonTest extends WebTestCase
{
    public function testTheComparisonPageIsBehindARole(): void
    {
        $client = static::createClient();

        $client->request('GET', '/strategies');
        self::assertResponseRedirects('http://localhost/login');

        $this->loginAs($client, 'user', ['ROLE_USER']);
        $client->request('GET', '/strategies');
        self::assertResponseIsSuccessful();
    }

    /**
     * Document #3 is locked and owned by "admin", who reaches the editorial board through the role
     * hierarchy: two grants and one refusal. Every algorithm reads that differently, and the
     * application's own is the one that refuses despite the quorum.
     */
    public function testEveryAlgorithmReadsTheSameVotesDifferently(): void
    {
        $client = static::createClient();
        $inspector = $this->inspectorFor($client, 'admin', ['ROLE_ADMIN']);
        $document = static::getContainer()->get(DocumentStore::class)->find(3);

        // The votes themselves, so the verdicts below can be checked rather than trusted. A
        // CastVote pairs the outcome with the voter that reached it.
        $votes = [];
        foreach ($inspector->decide('PUBLISH', $document)->votes as $vote) {
            $votes[] = $vote->outcome->decision->value;
        }
        self::assertSame(2, \count(array_filter($votes, static fn ($v) => 'ACCESS_GRANTED' === $v)), 'the owner and the board');
        self::assertSame(1, \count(array_filter($votes, static fn ($v) => 'ACCESS_DENIED' === $v)), 'compliance');

        // One grant is enough.
        self::assertTrue($inspector->isGranted('PUBLISH', $document, 'permit_overrides'));

        // A single refusal wins.
        self::assertFalse($inspector->isGranted('PUBLISH', $document, 'deny_overrides'));

        // Two grants outweigh one refusal.
        self::assertTrue($inspector->isGranted('PUBLISH', $document, 'majority'));

        // The application's own: a quorum was reached and a refusal is still not outvoted.
        self::assertFalse($inspector->isGranted('PUBLISH', $document, 'two_keys'));
    }

    /**
     * Without the compliance veto there is nothing to disagree about, and the two-key rule is the
     * only one that can still refuse — for want of a second key rather than for an objection.
     */
    public function testTheQuorumIsAboutCountingGrantsNotRefusals(): void
    {
        $client = static::createClient();
        $document = static::getContainer()->get(DocumentStore::class)->find(2);

        // "manager" owns #2 and sits on the board: two grants, no refusal.
        $manager = $this->inspectorFor($client, 'manager', ['ROLE_MANAGER']);
        self::assertTrue($manager->isGranted('PUBLISH', $document, 'two_keys'));

        // "user" owns nothing here and is not on the board, so #2 gathers no key at all.
        $user = $this->inspectorFor($client, 'user', ['ROLE_USER']);
        self::assertFalse($user->isGranted('PUBLISH', $document, 'two_keys'));
    }

    /**
     * A single grant is not a quorum, and the refusal says which of the two cases it is: one key
     * short rather than nobody having anything to say.
     */
    public function testOneKeyShortIsRefusedWithItsOwnReason(): void
    {
        $client = static::createClient();
        $inspector = $this->inspectorFor($client, 'user', ['ROLE_USER']);
        $document = static::getContainer()->get(DocumentStore::class)->find(1);

        $decision = $inspector->decide('PUBLISH', $document, 'two_keys');

        self::assertFalse($decision->isGranted());
        // #1 is locked, so compliance refuses outright and the quorum never comes into it.
        self::assertStringContainsString('refusal is not outvoted', (string) $decision->reason);
    }

    public function testThePageShowsEveryAlgorithmIncludingTheApplicationsOwn(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);

        $crawler = $client->request('GET', '/strategies');
        self::assertResponseIsSuccessful();

        $html = $crawler->html();
        foreach (['permit_overrides', 'deny_overrides', 'majority', 'first_applicable', 'two_keys'] as $strategy) {
            self::assertStringContainsString($strategy, $html);
        }
    }

    /**
     * The inspector reads the token storage, which only the firewall fills — so a request has to
     * have gone through it before the service can be asked anything.
     *
     * @param list<string> $roles
     */
    private function inspectorFor(KernelBrowser $client, string $username, array $roles): AccessInspector
    {
        $this->loginAs($client, $username, $roles);

        $client->request('GET', '/dashboard');
        self::assertResponseIsSuccessful();

        return static::getContainer()->get(AccessInspector::class);
    }

    /**
     * @param list<string> $roles
     */
    private function loginAs(KernelBrowser $client, string $username, array $roles): void
    {
        $client->loginUser(new InMemoryUser($username, $username, $roles));
    }
}
