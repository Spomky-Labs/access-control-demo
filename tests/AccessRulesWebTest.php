<?php

declare(strict_types=1);

namespace App\Tests;

use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * Exercises the declarative `access_control.rules`: the /zone area is guarded entirely by
 * config, ZoneController carrying no attribute. Denials are raised on kernel.request and
 * handled by the firewall through the shared AccessDeniedExceptionInterface.
 */
final class AccessRulesWebTest extends WebTestCase
{
    public function testZoneIndexHasNoRuleAndStaysPublic(): void
    {
        $client = static::createClient();
        $client->request('GET', '/zone');

        self::assertResponseIsSuccessful();
    }

    public function testMembersRuleRedirectsAnonymousToLogin(): void
    {
        $client = static::createClient();
        $client->request('GET', '/zone/members');

        self::assertResponseRedirects('http://localhost/login');
    }

    public function testMembersRuleAcceptsAnyAuthenticatedUser(): void
    {
        $client = static::createClient();
        $this->loginAs($client, 'user', ['ROLE_USER']);

        $client->request('GET', '/zone/members');
        self::assertResponseIsSuccessful();
    }

    public function testStaffRuleAppliesRoleHierarchy(): void
    {
        $client = static::createClient();

        $this->loginAs($client, 'user', ['ROLE_USER']);
        $client->request('GET', '/zone/staff');
        self::assertResponseStatusCodeSame(403, 'a plain user is not staff');

        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);
        $client->request('GET', '/zone/staff');
        self::assertResponseIsSuccessful();

        // ROLE_ADMIN inherits ROLE_MANAGER through the hierarchy.
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);
        $client->request('GET', '/zone/staff');
        self::assertResponseIsSuccessful();
    }

    public function testAdminRuleRejectsManager(): void
    {
        $client = static::createClient();

        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);
        $client->request('GET', '/zone/admin');
        self::assertResponseStatusCodeSame(403);

        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);
        $client->request('GET', '/zone/admin');
        self::assertResponseIsSuccessful();
    }

    public function testAllowIfExpressionGrantsByClientIpWithoutAnyRole(): void
    {
        $client = static::createClient();

        // Default test client IP is 127.0.0.1: granted, even without signing in.
        $client->request('GET', '/zone/local');
        self::assertResponseIsSuccessful();

        // Same rule, different origin: refused. Signed in so the firewall answers 403
        // rather than redirecting to login, proving the denial is the rule's, not the auth's.
        $this->loginAs($client, 'admin', ['ROLE_ADMIN']);
        $client->request('GET', '/zone/local', [], [], ['REMOTE_ADDR' => '203.0.113.7']);
        self::assertResponseStatusCodeSame(403);
    }

    public function testMethodScopedRuleLeavesGetOpenButGuardsPost(): void
    {
        $client = static::createClient();

        // GET matches no rule: open to everyone.
        $client->request('GET', '/zone/api');
        self::assertResponseIsSuccessful();

        // POST is covered by the rule and needs ROLE_MANAGER.
        $client->request('POST', '/zone/api');
        self::assertResponseRedirects('http://localhost/login', null, 'anonymous POST redirects to login');

        $this->loginAs($client, 'user', ['ROLE_USER']);
        $client->request('POST', '/zone/api');
        self::assertResponseStatusCodeSame(403, 'a plain user may not write');

        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);
        $client->request('POST', '/zone/api');
        self::assertResponseIsSuccessful();
    }

    /**
     * @param list<string> $roles
     */
    private function loginAs(KernelBrowser $client, string $username, array $roles): void
    {
        $client->loginUser(new InMemoryUser($username, $username, $roles));
    }
}
