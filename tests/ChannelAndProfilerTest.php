<?php

declare(strict_types=1);

namespace App\Tests;

use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The two parts of the bundle nothing else in this suite reaches: the channel a rule may require,
 * and the profiler panel.
 */
final class ChannelAndProfilerTest extends WebTestCase
{
    /**
     * A channel is not a permission. An insecure request is redirected rather than refused, and
     * the listener that does it runs ahead of the one that would have decided anything.
     */
    public function testAnInsecureRequestIsRedirectedRatherThanRefused(): void
    {
        $client = static::createClient();

        // Anonymous and over plain HTTP: the channel is corrected first, so this is a redirect to
        // HTTPS and not the trip to the login form the ROLE_USER on the same rule would cause.
        $client->request('GET', 'http://localhost/zone/secure');

        self::assertResponseRedirects();
        self::assertStringStartsWith('https://localhost/zone/secure', $client->getResponse()->headers->get('Location'));
    }

    /**
     * Once the transport is right, the rest of the rule applies as any other rule does.
     */
    public function testTheRoleOnTheSameRuleStillApplies(): void
    {
        $client = static::createClient();

        $client->request('GET', 'https://localhost/zone/secure');
        self::assertResponseRedirects('https://localhost/login', null, 'secure, but nobody is asking');

        $this->loginAs($client, 'user', ['ROLE_USER']);
        $client->request('GET', 'https://localhost/zone/secure');
        self::assertResponseIsSuccessful();
    }

    /**
     * The rules and the channel go together: whichever key declares the URL rules enforces the
     * channel too, and the firewall's own channel listener is pulled out of every chain — leaving
     * it in would redirect twice for one rule.
     */
    public function testTheComponentOwnsTheChannelAndRedirectsOnlyOnce(): void
    {
        $client = static::createClient();
        $container = static::getContainer()->get('test.service_container');

        // Registered only because a rule declares a channel; without one it is compiled away.
        self::assertTrue($container->has('access_control.listener.channel'));

        $this->loginAs($client, 'user', ['ROLE_USER']);
        $client->request('GET', 'http://localhost/zone/secure');

        // One redirect, and the page on the other side of it. A second listener in the chain would
        // show up here as a redirect to the very URL just reached.
        self::assertResponseRedirects();
        $client->followRedirect();
        self::assertResponseIsSuccessful();
    }

    /**
     * The profiler panel, which is what a developer actually looks at when a decision surprises
     * them. Rendering it exercises the data collector and the bundle's Twig template.
     */
    public function testTheProfilerPanelCollectsTheRequestsDecisions(): void
    {
        $client = static::createClient();
        $client->enableProfiler();
        $this->loginAs($client, 'user', ['ROLE_USER']);

        $client->request('GET', '/documents/1');
        self::assertResponseIsSuccessful();

        $profile = $client->getProfile();
        self::assertNotFalse($profile, 'the profiler is on in the test environment');

        $collector = $profile->getCollector('access_control');

        // The page carries a class-level policy and a method-level one.
        self::assertSame(2, $collector->getDecisionCount());
        self::assertSame(2, $collector->getGrantedCount());
        self::assertSame(0, $collector->getDeniedCount());

        // The panel names the algorithm in the word the application wrote rather than in the
        // component's translation of it — the same reasoning as access_decision().strategy.
        self::assertSame('permit_overrides', $collector->getDefaultStrategy());
        self::assertSame('affirmative', $collector->getDefaultStrategyAlias());

        // The Integration section: what the bridge took over, which is the first thing to look at
        // when a decision surprises somebody.
        self::assertNotEmpty($collector->getIntegration());
        self::assertNotEmpty($collector->getVoters(), 'the application voters are listed');
    }

    public function testThePanelItselfRenders(): void
    {
        $client = static::createClient();
        $client->enableProfiler();
        $this->loginAs($client, 'manager', ['ROLE_MANAGER']);

        // A refusal, so the panel has something interesting to show.
        $client->request('GET', '/documents/1');
        self::assertResponseStatusCodeSame(403);

        $token = $client->getProfile()->getToken();

        $crawler = $client->request('GET', '/_profiler/'.$token.'?panel=access_control');
        self::assertResponseIsSuccessful();

        $html = $crawler->html();
        self::assertStringContainsString('VIEW', $html, 'the refused attribute is named');
        self::assertStringContainsString('DocumentVoter', $html, 'and so is the voter that refused it');
    }

    /**
     * @param list<string> $roles
     */
    private function loginAs(KernelBrowser $client, string $username, array $roles): void
    {
        $client->loginUser(new InMemoryUser($username, $username, $roles));
    }
}
