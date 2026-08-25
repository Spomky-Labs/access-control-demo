<?php

declare(strict_types=1);

namespace App\Tests;

use App\Tests\Standalone\SecurityRulesKernel;
use App\Tests\Standalone\VaultVoter;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The rules of `security.access_control`, enforced by the AccessControl component.
 *
 * An application declares them where it always did; registering the bundle moves where they are
 * applied, without a line of security.yaml changing.
 */
final class SecurityRulesTakeoverTest extends TestCase
{
    private static SecurityRulesKernel $kernel;

    public static function setUpBeforeClass(): void
    {
        self::$kernel = new SecurityRulesKernel();
        self::$kernel->boot();
    }

    public static function tearDownAfterClass(): void
    {
        self::$kernel->shutdown();
    }

    /**
     * The rules of security.access_control were rebuilt as the component's own, and it is the
     * component's listener that now carries them.
     */
    public function testTheRulesOfSecurityBecameTheComponents(): void
    {
        $container = self::$kernel->getContainer()->get('test.service_container');

        self::assertTrue($container->has('access_control.rule_map'), 'the component built a rule map');
        self::assertTrue($container->has('access_control.listener.access_rule'), 'and enforces it');

        // The firewall's own access listener is gone: leaving it in would apply each rule twice.
        self::assertFalse($container->has('security.access_listener'));
    }

    /**
     * The decisive one: ROLE_VAULT is held by nobody, and only VaultVoter can grant it — a voter
     * of the component alone, which Security's access listener would never consult.
     *
     * Granting on its vote proves two things at once: the component applies the rule, and the
     * firewall no longer does — had its listener stayed in the chain, it would have denied the
     * very same request, knowing nothing of this voter.
     */
    public function testAComponentOnlyVoterDecidesARuleOfSecuritysKey(): void
    {
        // Signed in as alice, who holds ROLE_USER and no ROLE_VAULT: the voter abstains for want
        // of a token, the RoleVoter denies, and the firewall answers 403 for an identified user.
        self::assertSame(403, $this->get('/vault', vaultToken: null)->getStatusCode());

        // With the token, the component's voter grants and the rule lets the request through.
        self::assertSame(200, $this->get('/vault', vaultToken: 'open-sesame')->getStatusCode());
    }

    public function testOrdinaryRoleRulesStillBehave(): void
    {
        // Authenticated with ROLE_USER: granted.
        self::assertSame(200, $this->get('/members', authenticated: true)->getStatusCode());

        // Anonymous: refused. Behind a firewall the exception listener answers, so this is a 401
        // (http_basic challenge) rather than the bare 403 the exception carries on its own.
        self::assertSame(401, $this->get('/members', authenticated: false)->getStatusCode());
    }

    public function testAPathNoRuleCoversStaysOpen(): void
    {
        self::assertSame(200, $this->get('/open', authenticated: false)->getStatusCode());
    }

    /**
     * Declaring rules on both keys is refused rather than merged: the union of two rule sets is
     * neither of them, and silently applying it would guard paths nobody asked to guard.
     */
    public function testDeclaringRulesOnBothKeysIsRefused(): void
    {
        $kernel = new SecurityRulesKernel(alsoDeclareComponentRules: true);

        $this->expectException(\Symfony\Component\DependencyInjection\Exception\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/declared under both .*security\.access_control.* and .*access_control\.rules/i');

        $kernel->boot();
    }

    public function testTheVoterIsTaggedForTheComponentOnly(): void
    {
        // Sanity check on the probe itself: it is not a Security voter and could not be one.
        self::assertFalse(is_subclass_of(VaultVoter::class, \Symfony\Component\Security\Core\Authorization\Voter\VoterInterface::class));
    }

    private function get(string $path, bool $authenticated = true, ?string $vaultToken = null): Response
    {
        $server = [];

        if ($authenticated) {
            $server['PHP_AUTH_USER'] = 'alice';
            $server['PHP_AUTH_PW'] = 'pa$$word';
        }

        $request = Request::create($path, server: $server);

        if (null !== $vaultToken) {
            $request->headers->set('X-Vault-Token', $vaultToken);
        }

        return self::$kernel->handle($request);
    }
}
