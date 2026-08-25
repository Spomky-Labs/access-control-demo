<?php

declare(strict_types=1);

namespace App\Tests;

use AccessControl\AccessControlManagerInterface;
use AccessControl\AccessRequest;
use AccessControl\DecisionVote;
use AccessControl\Requester\Actor;
use App\Security\ActingAdminVoter;
use App\Security\OnBehalfOfSession;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * Drives the component-native delegation (DelegatedRequesterInterface + Actor) and the app's
 * ActingAdminVoter straight through the AccessControlManager, no HTTP or firewall involved.
 */
final class OnBehalfOfTest extends KernelTestCase
{
    private AccessControlManagerInterface $manager;

    protected function setUp(): void
    {
        self::bootKernel();
        $this->manager = self::getContainer()->get(AccessControlManagerInterface::class);
    }

    public function testCustomerAloneHasNoActorAndNoAdminPower(): void
    {
        $customer = new InMemoryUser('customer-42', null, ['ROLE_USER']);

        self::assertNull(Actor::of($customer), 'nobody is acting for a plain user');
        self::assertFalse($this->grants($customer, 'ROLE_ADMIN'));
        self::assertFalse($this->grants($customer, 'IS_IMPERSONATOR'));
        self::assertFalse($this->grants($customer, ActingAdminVoter::ATTRIBUTE));
    }

    public function testAdminAgentActsOnBehalfWithoutWideningTheCustomersRoles(): void
    {
        $agent = new UsernamePasswordToken(new InMemoryUser('support-agent', null, ['ROLE_ADMIN']), 'main', ['ROLE_ADMIN']);
        $session = new OnBehalfOfSession($agent, 'customer-42', ['ROLE_USER']);

        // The component finds the actor behind the requester...
        self::assertSame($agent, Actor::of($session));

        // ...the session keeps only the customer's own role...
        self::assertFalse($this->grants($session, 'ROLE_ADMIN'), 'delegation must not hand the customer admin rights');

        // ...yet the system knows somebody is acting, and that the actor is an admin.
        self::assertTrue($this->grants($session, 'IS_IMPERSONATOR'));
        self::assertTrue($this->grants($session, ActingAdminVoter::ATTRIBUTE));
    }

    public function testActingAdminIsDeniedWhenTheActorIsNotAnAdmin(): void
    {
        $agent = new UsernamePasswordToken(new InMemoryUser('desk-clerk', null, ['ROLE_USER']), 'main', ['ROLE_USER']);
        $session = new OnBehalfOfSession($agent, 'customer-42', ['ROLE_USER']);

        self::assertTrue($this->grants($session, 'IS_IMPERSONATOR'), 'someone is still acting');
        self::assertFalse($this->grants($session, ActingAdminVoter::ATTRIBUTE), 'but that someone is no admin');
    }

    private function grants(mixed $requester, string $attribute): bool
    {
        return DecisionVote::ACCESS_GRANTED === $this->manager->decide(new AccessRequest($requester, $attribute))->decision;
    }
}
