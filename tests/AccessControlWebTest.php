<?php

declare(strict_types=1);

namespace App\Tests;

use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * Exercises the full access matrix of the demo app, driving the real
 * AccessControl component through the HTTP kernel.
 */
final class AccessControlWebTest extends WebTestCase
{
    public function testPublicHomeIsOpenToEveryone(): void
    {
        $client = static::createClient();
        $client->request('GET', '/');

        self::assertResponseIsSuccessful();
    }

    public function testProtectedPagesRedirectAnonymousToLogin(): void
    {
        $client = static::createClient();

        foreach (['/dashboard', '/admin', '/documents'] as $path) {
            $client->request('GET', $path);
            self::assertResponseRedirects('http://localhost/login', null, "GET $path should redirect to login");
        }
    }

    public function testAnyAuthenticatedUserReachesTheDashboard(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'user', ['ROLE_USER']);

        $client->request('GET', '/dashboard');
        self::assertResponseIsSuccessful();
    }

    public function testAdminAreaRejectsPlainUserWithCustomMessage(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'user', ['ROLE_USER']);

        $client->request('GET', '/admin');
        self::assertResponseStatusCodeSame(403);
    }

    public function testAdminAreaAndReportsAcceptAdmin(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);

        $client->request('GET', '/admin');
        self::assertResponseIsSuccessful();

        $client->request('GET', '/admin/reports');
        self::assertResponseIsSuccessful();
    }

    public function testDocumentViewIsOwnerOrAdmin(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'user', ['ROLE_USER']);

        // #1 is owned by "user".
        $client->request('GET', '/documents/1');
        self::assertResponseIsSuccessful();

        // #2 is owned by "manager": a plain user may not view it.
        $client->request('GET', '/documents/2');
        self::assertResponseStatusCodeSame(403);
    }

    public function testDocumentEditIsOwnerOnly(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);

        // An admin may VIEW any document...
        $client->request('GET', '/documents/1');
        self::assertResponseIsSuccessful();

        // ...but EDIT is reserved to the owner, admins included.
        $client->request('GET', '/documents/1/edit');
        self::assertResponseStatusCodeSame(403);

        // #3 is owned by "admin": editing it is allowed.
        $client->request('GET', '/documents/3/edit');
        self::assertResponseIsSuccessful();
    }

    public function testAtLeastOneOfAcceptsEitherRole(): void
    {
        $client = static::createClient();

        $this->loginAs($client, 'user', ['ROLE_USER']);
        $client->request('GET', '/playground/either');
        self::assertResponseStatusCodeSame(403, 'a plain user has neither role');

        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);
        $client->request('GET', '/playground/either');
        self::assertResponseIsSuccessful();

        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);
        $client->request('GET', '/playground/either');
        self::assertResponseIsSuccessful();
    }

    public function testStrategyChangesTheOutcomeOnALockedDocument(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'user', ['ROLE_USER']);

        // Document #1 is owned by "user" and locked. Ownership grants, compliance vetoes.
        // permit_overrides: the grant wins.
        $client->request('GET', '/documents/1/publish');
        self::assertResponseIsSuccessful();

        // deny_overrides: the veto wins on the very same request.
        $client->request('GET', '/documents/1/publish-strict');
        self::assertResponseStatusCodeSame(403);
    }

    public function testStrategyIsIrrelevantWhenNoVeto(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);

        // Document #2 is owned by "manager" and not locked: compliance abstains, so both
        // strategies grant.
        $client->request('GET', '/documents/2/publish');
        self::assertResponseIsSuccessful();
        $client->request('GET', '/documents/2/publish-strict');
        self::assertResponseIsSuccessful();
    }

    public function testComplexExpressionCombinesRoleOwnershipAndAuthState(): void
    {
        $client = static::createClient();

        // Admin: granted anywhere (the ROLE_ADMIN branch).
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);
        $client->request('GET', '/documents/2/manage');
        self::assertResponseIsSuccessful();

        // Manager on their own document (#2): owner + ROLE_MANAGER branch.
        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);
        $client->request('GET', '/documents/2/manage');
        self::assertResponseIsSuccessful();

        // Manager on someone else's document (#1): neither branch holds.
        $client->request('GET', '/documents/1/manage');
        self::assertResponseStatusCodeSame(403);

        // Owner but not a manager (#1 belongs to "user"): the ROLE_MANAGER branch fails.
        $this->loginAs($client, 'user', ['ROLE_USER']);
        $client->request('GET', '/documents/1/manage');
        self::assertResponseStatusCodeSame(403);
    }

    public function testClosureVoterPageRendersForAuthenticatedUser(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'user', ['ROLE_USER']);

        $client->request('GET', '/playground/closure');
        self::assertResponseIsSuccessful();
        self::assertSelectorTextContains('h1', 'ClosureVoter');
    }

    public function testImpersonationUnlocksTheImpersonatorPage(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);

        // Not impersonating: IS_IMPERSONATOR is denied.
        $client->request('GET', '/playground/impersonation');
        self::assertResponseStatusCodeSame(403);

        // Switching user turns the token into a SwitchUserToken, which grants IS_IMPERSONATOR.
        // switch_user redirects to the same URL without the parameter, so follow it.
        $client->request('GET', '/playground/impersonation?_switch_user=user');
        self::assertResponseRedirects('http://localhost/playground/impersonation');
        $client->followRedirect();
        self::assertResponseIsSuccessful();
    }

    public function testProgrammaticPermissionsPage(): void
    {
        $client = static::createClient();

        // Anonymous: the in-code guard refuses, the firewall redirects to login.
        $client->request('GET', '/permissions');
        self::assertResponseRedirects('http://localhost/login');

        // Signed in: the matrix is built programmatically by AccessInspector.
        $this->loginAs($client, 'user', ['ROLE_USER']);
        $crawler = $client->request('GET', '/permissions');
        self::assertResponseIsSuccessful();
        self::assertSelectorTextContains('h1', 'Your permissions');
        // "user" owns document #1, so at least one grant reason is shown.
        self::assertStringContainsString('The owner may view the document.', $crawler->html());
    }

    public function testDelegatedAccessDecisionAgreesWithTheTakenOverIsGranted(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'user', ['ROLE_USER']);

        // Rendering exercises access_decision(), which the bundle delegates to Security while
        // taking is_granted() over. It used to fail at runtime; a 200 proves the delegation holds.
        $crawler = $client->request('GET', '/permissions');
        self::assertResponseIsSuccessful();

        $rows = $crawler->filter('table')->eq(1)->filter('tbody tr');
        self::assertGreaterThan(0, $rows->count(), 'the comparison table is rendered');

        foreach ($rows as $node) {
            $cells = (new \Symfony\Component\DomCrawler\Crawler($node))->filter('td')->each(
                static fn ($td) => trim($td->text()),
            );

            // Both columns must reach the same verdict for every document.
            $isGranted = str_contains($cells[1], 'granted') && !str_contains($cells[1], 'denied');
            $decision = str_contains($cells[2], '✅');
            self::assertSame($isGranted, $decision, "is_granted() and access_decision() disagree on: $cells[0]");
        }

        // The message comes from the component's own DocumentVoter, through Security's object.
        self::assertStringContainsString('The owner may view the document.', $crawler->html());
    }

    /**
     * The component publishes the same question under a name of its own, because
     * access_decision() hands back an object whose shape is Security's and cannot be given ours.
     * Both are on the page, and they must agree.
     */
    public function testTheComponentsOwnDecisionFunctionAgreesWithSecuritys(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'user', ['ROLE_USER']);

        $crawler = $client->request('GET', '/permissions');
        self::assertResponseIsSuccessful();

        $rows = $crawler->filter('table')->eq(2)->filter('tbody tr');
        self::assertGreaterThan(0, $rows->count(), 'the two-vocabularies table is rendered');

        foreach ($rows as $node) {
            $cells = (new \Symfony\Component\DomCrawler\Crawler($node))->filter('td')->each(
                static fn ($td) => trim($td->text()),
            );

            // Security's shape: a boolean. The component's: a three-valued enum.
            $legacy = str_contains($cells[1], '.isGranted = true');
            $native = str_contains($cells[2], 'ACCESS_GRANTED');

            self::assertSame($legacy, $native, "the two vocabularies disagree on: $cells[0]");
            self::assertStringContainsString('.isGranted() = '.($native ? 'true' : 'false'), $cells[2]);
        }
    }

    /**
     * access_decision().strategy went from naming an algorithm to saying nothing, the day the
     * bundle was installed and without an error. It names it again, and in the word Security uses:
     * this app writes permit_overrides on the component's key for the very same algorithm.
     */
    public function testTheDelegatedDecisionStillNamesTheCombiningAlgorithm(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'user', ['ROLE_USER']);

        $crawler = $client->request('GET', '/permissions');
        self::assertResponseIsSuccessful();

        $first = trim($crawler->filter('table')->eq(2)->filter('tbody tr')->eq(0)->filter('td')->eq(1)->text());

        self::assertStringContainsString('.strategy = affirmative', $first);
        self::assertStringNotContainsString('.strategy = —', $first);
    }

    public function testAccessPreviewIsAdminOnly(): void
    {
        $client = static::createClient();

        // Anonymous → login; plain user → 403.
        $client->request('GET', '/permissions/preview');
        self::assertResponseRedirects('http://localhost/login');

        $this->loginAs($client, 'user', ['ROLE_USER']);
        $client->request('GET', '/permissions/preview');
        self::assertResponseStatusCodeSame(403);
    }

    public function testAccessPreviewDecidesForOtherUsersInTheTemplate(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);

        // Rendering the page runs is_granted_for_user() for every cell; a 200 proves the
        // component answers it under the firewall. The matrix must expose the role hierarchy:
        // the manager row is granted ROLE_USER while the user row is not.
        $crawler = $client->request('GET', '/permissions/preview');
        self::assertResponseIsSuccessful();
        self::assertSelectorTextContains('h1', 'Access preview');

        $cells = static function (\Symfony\Component\DomCrawler\Crawler $row): array {
            return $row->filter('td')->each(static fn ($td) => trim($td->text()));
        };

        // Columns: Account, PUBLIC_ACCESS, ROLE_USER, ROLE_MANAGER, ROLE_ADMIN, ROLE_ALLOWED_TO_SWITCH.
        // The first table only: the page also carries the "and why" one, whose rows name the very
        // same accounts.
        $rowsByAccount = [];
        foreach ($crawler->filter('table')->eq(0)->filter('tbody tr') as $node) {
            $row = $cells(new \Symfony\Component\DomCrawler\Crawler($node));
            $rowsByAccount[$row[0]] = $row;
        }

        self::assertSame('✓', $rowsByAccount['user'][2], 'user holds ROLE_USER');
        self::assertSame('✗', $rowsByAccount['user'][3], 'user does not hold ROLE_MANAGER');
        self::assertSame('✓', $rowsByAccount['manager'][2], 'manager holds ROLE_USER through the hierarchy');
        self::assertSame('✓', $rowsByAccount['admin'][5], 'admin holds ROLE_ALLOWED_TO_SWITCH through the hierarchy');
        self::assertSame('✓', $rowsByAccount['anonymous'][1], 'PUBLIC_ACCESS is granted to everyone');
        self::assertSame('✗', $rowsByAccount['anonymous'][2], 'anonymous holds no role');
    }

    /**
     * A ✓ says what, never why. access_control_decision_for_user() hands back the whole decision,
     * so the reason the voters wrote reaches a page that is deciding for somebody else.
     */
    public function testAccessPreviewExplainsWhyForOtherUsers(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);

        $crawler = $client->request('GET', '/permissions/preview');
        self::assertResponseIsSuccessful();

        $verdicts = [];
        foreach ($crawler->filter('table')->eq(1)->filter('tbody tr') as $node) {
            $row = (new \Symfony\Component\DomCrawler\Crawler($node))->filter('td')->each(
                static fn ($td) => trim($td->text()),
            );
            $verdicts[$row[0]] = ['decision' => $row[1], 'reason' => $row[2]];
        }

        // ROLE_MANAGER: held outright, reached through the hierarchy, and out of reach.
        self::assertSame('ACCESS_GRANTED', $verdicts['manager']['decision']);
        self::assertSame('ACCESS_GRANTED', $verdicts['admin']['decision'], 'ROLE_ADMIN reaches ROLE_MANAGER');
        self::assertSame('ACCESS_DENIED', $verdicts['user']['decision']);
        self::assertSame('ACCESS_DENIED', $verdicts['anonymous']['decision']);

        // The whole point of the column: a verdict that says something.
        self::assertNotSame('—', $verdicts['manager']['reason']);
        self::assertNotSame('—', $verdicts['user']['reason']);
    }

    public function testPlaygroundOffersImpersonationLinksViaTwigHelper(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);

        $crawler = $client->request('GET', '/playground');
        self::assertResponseIsSuccessful();

        // impersonation_path('user') builds the switch_user link for the current route.
        $hrefs = $crawler->filter('a')->each(static fn ($a) => $a->attr('href'));
        self::assertContains('/playground?_switch_user=user', $hrefs);
    }

    public function testOnBehalfPageContrastsRequesterAndActor(): void
    {
        $client = static::createClient();

        // Public page, decided programmatically for explicit requesters — no login needed.
        $crawler = $client->request('GET', '/playground/on-behalf');
        self::assertResponseIsSuccessful();
        self::assertSelectorTextContains('h1', 'Acting on behalf of');

        // The delegated row names the real actor, the admin agent behind the customer session.
        self::assertStringContainsString('support-agent', $crawler->html());
    }

    /**
     * @param list<string> $roles
     */
    private function loginAs(KernelBrowser $client, string $username, array $roles): void
    {
        $client->loginUser(new InMemoryUser($username, $username, $roles));
    }
}
