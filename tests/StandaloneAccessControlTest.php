<?php

declare(strict_types=1);

namespace App\Tests;

use App\Tests\Standalone\StandaloneKernel;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The component standing on its own: FrameworkBundle + AccessControlBundle, no SecurityBundle.
 *
 * What it proves is that the role hierarchy, the declarative rules and the #[AccessPolicy]
 * attribute all work with no firewall, no token and no user provider — the hierarchy being
 * declared on the component's own `access_control.role_hierarchy` key.
 */
final class StandaloneAccessControlTest extends TestCase
{
    private static StandaloneKernel $kernel;

    public static function setUpBeforeClass(): void
    {
        self::$kernel = new StandaloneKernel();
        self::$kernel->boot();
    }

    public static function tearDownAfterClass(): void
    {
        self::$kernel->shutdown();
    }

    public function testTheBundleRunsWithoutSecurityAtAll(): void
    {
        $bundles = array_keys(self::$kernel->getBundles());

        self::assertContains('AccessControlBundle', $bundles);
        self::assertNotContains('SecurityBundle', $bundles);
        self::assertFalse(self::$kernel->getContainer()->has('security.token_storage'), 'no Security in this kernel');
    }

    public function testHierarchyDeclaredOnTheComponentsOwnKeyIsApplied(): void
    {
        // The admin key holds ROLE_ADMIN alone and must reach the two roles below it.
        $answers = $this->json('/whoami', 'key-admin');

        self::assertTrue($answers['admin']);
        self::assertTrue($answers['editor'], 'ROLE_ADMIN reaches ROLE_EDITOR');
        self::assertTrue($answers['reader'], 'and ROLE_EDITOR reaches ROLE_READER, transitively');
    }

    public function testHierarchyIsDirectionalNotSymmetric(): void
    {
        $answers = $this->json('/whoami', 'key-reader');

        self::assertTrue($answers['reader']);
        self::assertFalse($answers['editor'], 'a reader does not climb the hierarchy');
        self::assertFalse($answers['admin']);
    }

    public function testPublicAccessIsGrantedEvenWithoutAnyRequester(): void
    {
        // No API key at all: the provider returns null, so nobody is asking.
        $answers = $this->json('/whoami', null);

        self::assertTrue($answers['public'], 'PUBLIC_ACCESS is not a role');
        self::assertFalse($answers['reader']);
    }

    public function testDeclarativeRuleGuardsTheArchiveWithoutAFirewall(): void
    {
        // The editor key reaches ROLE_READER through the hierarchy, so the rule grants.
        self::assertSame(200, $this->request('/archive', 'key-editor')->getStatusCode());

        // Nobody: the rule denies, and with no firewall to redirect, the exception's own
        // #[WithHttpStatus(403)] is what answers.
        self::assertSame(403, $this->request('/archive', null)->getStatusCode());
    }

    public function testAccessPolicyAttributeGuardsTheControllerWithoutAFirewall(): void
    {
        self::assertSame(200, $this->request('/publish', 'key-admin')->getStatusCode());
        self::assertSame(200, $this->request('/publish', 'key-editor')->getStatusCode());
        self::assertSame(403, $this->request('/publish', 'key-reader')->getStatusCode(), 'a reader may not publish');
    }

    public function testHierarchyIsWalkedBothWays(): void
    {
        // Downwards: what an admin reaches. This is the question every voter asks.
        $down = $this->json('/hierarchy?role=ROLE_ADMIN', null);
        self::assertSame(['ROLE_ADMIN', 'ROLE_EDITOR', 'ROLE_READER'], $this->sorted($down['reaches']));
        self::assertSame(['ROLE_ADMIN'], $this->sorted($down['reached_by']), 'nothing stands above an admin');

        // Upwards: who reaches a reader. getParentRoleNames() answers the inverse question,
        // transitively — it is public API no voter uses, carried across so Security's can go.
        $up = $this->json('/hierarchy?role=ROLE_READER', null);
        self::assertSame(['ROLE_READER'], $this->sorted($up['reaches']), 'a reader reaches nothing below');
        self::assertSame(['ROLE_ADMIN', 'ROLE_EDITOR', 'ROLE_READER'], $this->sorted($up['reached_by']));
    }

    /**
     * @param list<string> $roles
     *
     * @return list<string>
     */
    private function sorted(array $roles): array
    {
        sort($roles);

        return $roles;
    }

    /**
     * @return array<string, mixed>
     */
    private function json(string $path, ?string $apiKey): array
    {
        $response = $this->request($path, $apiKey);
        self::assertSame(200, $response->getStatusCode());

        return json_decode($response->getContent(), true, flags: \JSON_THROW_ON_ERROR);
    }

    private function request(string $path, ?string $apiKey): Response
    {
        $request = Request::create($path);

        if (null !== $apiKey) {
            $request->headers->set('X-Api-Key', $apiKey);
        }

        return self::$kernel->handle($request);
    }
}
