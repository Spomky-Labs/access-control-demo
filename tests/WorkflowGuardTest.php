<?php

declare(strict_types=1);

namespace App\Tests;

use AccessControl\Bridge\Workflow\GuardListener as AccessControlGuardListener;
use App\Tests\Standalone\MutableRequesterProvider;
use App\Tests\Standalone\WorkflowActor;
use App\Tests\Standalone\WorkflowDocument;
use App\Tests\Standalone\WorkflowKernel;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Workflow\EventListener\GuardListener as WorkflowGuardListener;
use Symfony\Component\Workflow\TransitionBlocker;
use Symfony\Component\Workflow\WorkflowInterface;

/**
 * A workflow guard in an application that has no Security at all.
 *
 * Workflow's guard listener needs four services of SecurityBundle and refuses to compile without
 * them, so `guard:` was until now something only an application with a firewall could write.
 * Registering AccessControlBundle swaps that listener for one of this component, and the very same
 * expressions keep deciding.
 *
 * Both shapes are booted here from one configuration, so what is measured is that they agree.
 */
final class WorkflowGuardTest extends TestCase
{
    private static WorkflowKernel $standalone;

    public static function setUpBeforeClass(): void
    {
        self::$standalone = new WorkflowKernel();
        self::$standalone->boot();
    }

    public static function tearDownAfterClass(): void
    {
        self::$standalone->shutdown();
    }

    /**
     * Without Security the listener is this component's; with it, Workflow's own is left in place,
     * the guards of such an application already reaching the component through the adapter on
     * security.access.decision_manager.
     */
    public function testTheListenerIsSwappedOnlyWhereSecurityIsAbsent(): void
    {
        self::assertInstanceOf(AccessControlGuardListener::class, self::$standalone->getContainer()->get(WorkflowKernel::GUARD_LISTENER));

        $withSecurity = new WorkflowKernel(withSecurity: true);
        $withSecurity->boot();

        try {
            $listener = $withSecurity->getContainer()->get(WorkflowKernel::GUARD_LISTENER);

            self::assertInstanceOf(WorkflowGuardListener::class, $listener);
            self::assertNotInstanceOf(AccessControlGuardListener::class, $listener);
        } finally {
            $withSecurity->shutdown();
        }
    }

    public function testAWorkflowRunsWithoutASingleSecurityService(): void
    {
        self::assertFalse(self::$standalone->getContainer()->has('security.token_storage'));
        self::assertInstanceOf(WorkflowInterface::class, self::$standalone->getContainer()->get(WorkflowKernel::WORKFLOW));
    }

    /**
     * The role hierarchy declared on the component's own key is applied inside a guard: nobody
     * holds ROLE_ADMIN and ROLE_EDITOR both, yet an admin satisfies the editor guard.
     */
    public function testARoleGuardIsDecidedByTheComponent(): void
    {
        $document = $this->reviewed(author: 'wanda');

        self::assertFalse($this->canAs('key-reader', ['ROLE_READER'], 'publish', $document));
        self::assertTrue($this->canAs('erin', ['ROLE_EDITOR'], 'publish', $document));
        self::assertTrue($this->canAs('adele', ['ROLE_ADMIN'], 'publish', $document), 'ROLE_ADMIN reaches ROLE_EDITOR');
    }

    /**
     * The subject and the requester in one expression — the four-eyes rule. Both variables are the
     * ones an access rule sees, the expression voter being reused rather than rebuilt.
     */
    public function testTheSubjectIsReachableFromAGuard(): void
    {
        self::assertTrue($this->canAs('erin', ['ROLE_EDITOR'], 'publish', $this->reviewed(author: 'wanda')));
        self::assertFalse($this->canAs('erin', ['ROLE_EDITOR'], 'publish', $this->reviewed(author: 'erin')), 'an editor may not publish what they wrote');
    }

    /**
     * is_valid() is Workflow's addition and has nothing to do with access. It is served by an
     * expression language of its own, so that an access rule does not gain a Validator function on
     * the way — and it works here with no Security in sight.
     */
    public function testIsValidIsServedByTheDedicatedExpressionLanguage(): void
    {
        $blank = new WorkflowDocument(author: 'wanda');
        $titled = new WorkflowDocument(author: 'wanda', title: 'Quarterly report');

        self::assertFalse($this->canAs('wanda', ['ROLE_READER'], 'submit', $blank), 'a blank title fails the constraint');
        self::assertTrue($this->canAs('wanda', ['ROLE_READER'], 'submit', $titled));
    }

    /**
     * Two transitions leave `draft`, guarded differently, and every guard of a workflow is
     * dispatched to the same listener: telling them apart is what the transition of a guard is for.
     */
    public function testEachTransitionIsGuardedOnItsOwn(): void
    {
        $draft = new WorkflowDocument(author: 'wanda', title: 'Quarterly report');

        $reader = $this->enabledAs('wanda', ['ROLE_READER'], $draft);
        self::assertSame(['submit'], $reader, 'a reader may submit but not discard');

        $admin = $this->enabledAs('adele', ['ROLE_ADMIN'], $draft);
        sort($admin);
        self::assertSame(['discard', 'submit'], $admin);
    }

    /**
     * A blocked transition says so as Workflow has always said it, with the blocker the expression
     * guard raises — the caller cannot tell which listener answered.
     */
    public function testABlockedTransitionCarriesTheExpressionGuardBlocker(): void
    {
        $this->actAs('erin', ['ROLE_EDITOR']);

        $blockers = $this->workflow()->buildTransitionBlockerList($this->reviewed(author: 'erin'), 'publish');

        self::assertCount(1, $blockers);
        self::assertSame(
            TransitionBlocker::BLOCKED_BY_EXPRESSION_GUARD_LISTENER,
            $blockers->getIterator()->current()->getCode(),
        );
    }

    /**
     * The other shape, end to end: with SecurityBundle the guards are Workflow's listener's to
     * evaluate, and the answers are the same — that listener asks the authorization checker, which
     * the bridge has already pointed at this component.
     */
    public function testTheSameGuardsGiveTheSameAnswersWithSecurity(): void
    {
        $kernel = new WorkflowKernel(withSecurity: true);
        $kernel->boot();

        try {
            $container = $kernel->getContainer()->get('test.service_container');
            $workflow = $kernel->getContainer()->get(WorkflowKernel::WORKFLOW);

            $signIn = static function (string $name, array $roles) use ($container): void {
                $user = new InMemoryUser($name, null, $roles);
                $container->get('security.token_storage')->setToken(new UsernamePasswordToken($user, 'main', $roles));
            };

            $signIn('erin', ['ROLE_EDITOR']);
            self::assertTrue($workflow->can($this->reviewed(author: 'wanda'), 'publish'));
            self::assertFalse($workflow->can($this->reviewed(author: 'erin'), 'publish'), 'the four-eyes rule holds here too');
            self::assertFalse($workflow->can(new WorkflowDocument(author: 'erin', title: 'Ok'), 'discard'));

            $signIn('adele', ['ROLE_ADMIN']);
            self::assertTrue($workflow->can(new WorkflowDocument(author: 'erin', title: 'Ok'), 'discard'));
        } finally {
            $kernel->shutdown();
        }
    }

    private function reviewed(string $author): WorkflowDocument
    {
        $document = new WorkflowDocument($author, 'Quarterly report');
        $document->marking = 'in_review';

        return $document;
    }

    /**
     * @param list<string> $roles
     */
    private function canAs(string $identifier, array $roles, string $transition, WorkflowDocument $document): bool
    {
        $this->actAs($identifier, $roles);

        return $this->workflow()->can($document, $transition);
    }

    /**
     * @param list<string> $roles
     *
     * @return list<string>
     */
    private function enabledAs(string $identifier, array $roles, WorkflowDocument $document): array
    {
        $this->actAs($identifier, $roles);

        return array_map(
            static fn ($transition) => $transition->getName(),
            $this->workflow()->getEnabledTransitions($document),
        );
    }

    /**
     * @param list<string> $roles
     */
    private function actAs(string $identifier, array $roles): void
    {
        self::$standalone->getContainer()
            ->get(MutableRequesterProvider::class)
            ->setRequester(new WorkflowActor($identifier, $roles));
    }

    private function workflow(): WorkflowInterface
    {
        return self::$standalone->getContainer()->get(WorkflowKernel::WORKFLOW);
    }
}
