<?php

declare(strict_types=1);

namespace App\Tests;

use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The publication workflow, guarded by the very voters the controllers use.
 *
 * This application has Security, so Workflow's own guard listener stays in place — and that is
 * what is measured here: it asks the authorization checker, which the bridge pointed at this
 * component, so a `guard:` expression naming EDIT is answered by DocumentVoter. The shape with no
 * Security at all is covered by WorkflowGuardTest.
 */
final class DocumentWorkflowTest extends WebTestCase
{
    /**
     * Document #1 is a draft owned by "user". EDIT is the owner's alone, so `submit` is the
     * owner's alone — even though an administrator may VIEW the very same document.
     */
    public function testATransitionGuardIsAnsweredByTheApplicationsVoter(): void
    {
        $client = static::createClient();

        $this->loginAs($client, 'user', ['ROLE_USER']);
        self::assertTrue($this->transition($client, 1, 'submit')['enabled'], 'the owner may submit their draft');

        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);
        $submit = $this->transition($client, 1, 'submit');
        self::assertFalse($submit['enabled'], 'an admin is not the owner, so EDIT refuses');
        self::assertStringContainsString('expression', strtolower($submit['blockers']), 'and the blocker names the guard expression');
    }

    /**
     * A transition out of reach because of the marking is not an access decision, and the blocker
     * list says so rather than blaming the guard.
     */
    public function testTheMarkingAndTheGuardBlockForDifferentReasons(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'user', ['ROLE_USER']);

        // #1 is in draft, so `publish` (from in_review) is unreachable whoever asks.
        $publish = $this->transition($client, 1, 'publish');
        self::assertFalse($publish['enabled']);
        self::assertStringContainsString('marking', strtolower($publish['blockers']));
    }

    /**
     * Two voters answer PUBLISH and a guard cannot name a strategy, so the default one applies:
     * permit_overrides, where the owner's grant beats the compliance veto. The same request under
     * deny_overrides is refused, which is what /publish-strict shows.
     */
    public function testTheDefaultStrategyDecidesAGuardWithTwoVoters(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);

        // #2 is in review, owned by "manager", and not locked: nobody vetoes, so a plain grant.
        self::assertTrue($this->transition($client, 2, 'publish')['enabled']);

        // #3 is in review too, but locked. ComplianceVoter denies and DocumentVoter grants, and
        // the guard is decided by permit_overrides — so the grant wins.
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);
        self::assertTrue(
            $this->transition($client, 3, 'publish')['enabled'],
            'permit_overrides lets the grant beat the compliance veto',
        );

        // The very same question under deny_overrides, which a controller may name and a guard
        // may not: there the veto wins.
        $client->request('GET', '/documents/3/publish-strict');
        self::assertResponseStatusCodeSame(403);
    }

    public function testARoleOnlyTransitionFollowsTheHierarchy(): void
    {
        $client = static::createClient();

        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);
        self::assertTrue($this->transition($client, 1, 'archive')['enabled']);

        // #2 belongs to "manager", who may view it — and still may not archive it.
        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);
        self::assertFalse($this->transition($client, 2, 'archive')['enabled'], 'archive is administrators only');
    }

    /**
     * The four-eyes rule inside a guard: a role, and the subject compared with who is asking.
     */
    public function testAGuardReadsTheSubjectAndTheRequesterTogether(): void
    {
        $client = static::createClient();

        // #4 is published and owned by "manager". An admin reaches ROLE_MANAGER through the
        // hierarchy and is not its owner, so both halves of the expression hold.
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);
        self::assertTrue($this->transition($client, 4, 'retract')['enabled']);

        // Its owner holds ROLE_MANAGER outright and is still refused, the second half of the
        // expression being about who they are rather than about what they hold.
        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);
        self::assertFalse($this->transition($client, 4, 'retract')['enabled'], 'the owner may not retract their own document');
    }

    /**
     * The page is guarded by an #[AccessPolicy] of its own, on a different attribute from the
     * transitions: looking at where a document stands is not moving it.
     */
    public function testThePageItselfIsGuardedByTheControllerPolicy(): void
    {
        $client = static::createClient();

        $client->request('GET', '/documents/1/workflow');
        self::assertResponseRedirects('http://localhost/login');

        // "manager" may not VIEW #1, which belongs to "user".
        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);
        $client->request('GET', '/documents/1/workflow');
        self::assertResponseStatusCodeSame(403);

        // An admin may VIEW any document, so the page opens — with every transition refused.
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);
        $client->request('GET', '/documents/1/workflow');
        self::assertResponseIsSuccessful();
    }

    /**
     * Applying goes through the same guards. A refusal is a Workflow error, not a 403: the
     * component decided the transition, and the page stays the requester's to see.
     */
    public function testApplyingATransitionIsGuardedToo(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'user', ['ROLE_USER']);

        $client->request('POST', '/documents/1/workflow/submit');
        self::assertResponseRedirects('/documents/1/workflow');
        $crawler = $client->followRedirect();
        self::assertStringContainsString('the document is now in_review', $crawler->filter('.flash-success')->text());

        // Refused by the guard: EDIT belongs to the owner, and "admin" is not it.
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);
        $client->request('POST', '/documents/1/workflow/submit');
        self::assertResponseRedirects('/documents/1/workflow');
        $crawler = $client->followRedirect();
        self::assertStringContainsString('was refused', $crawler->filter('.flash-error')->text());
    }

    /**
     * @return array{enabled: bool, blockers: string}
     */
    private function transition(KernelBrowser $client, int $document, string $name): array
    {
        $crawler = $client->request('GET', \sprintf('/documents/%d/workflow', $document));
        self::assertResponseIsSuccessful();

        foreach ($crawler->filter('tbody tr') as $node) {
            $cells = (new Crawler($node))->filter('td')->each(static fn ($td) => trim($td->text()));

            if ($name === $cells[0]) {
                return ['enabled' => str_contains($cells[2], 'allowed'), 'blockers' => $cells[2]];
            }
        }

        self::fail(\sprintf('No "%s" transition on the page.', $name));
    }

    /**
     * The password has to be the one security.yaml declares: InMemoryUser is EquatableInterface,
     * so a token whose user does not match the one the provider reloads is thrown away and the
     * request goes back to being anonymous.
     *
     * @param list<string> $roles
     */
    private function loginAs(KernelBrowser $client, string $username, array $roles): void
    {
        $client->loginUser(new InMemoryUser($username, $username, $roles));
    }
}
