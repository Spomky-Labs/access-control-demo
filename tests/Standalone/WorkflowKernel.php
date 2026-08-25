<?php

declare(strict_types=1);

namespace App\Tests\Standalone;

use AccessControl\Bundle\AccessControlBundle;
use Psr\Log\NullLogger;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * One guarded workflow, under the two shapes an application can have.
 *
 * A workflow guard is an expression, and until now evaluating it took Security: Workflow types its
 * GuardListener on four of its contracts and borrows its expression language. Registering
 * AccessControlBundle in an application that has no SecurityBundle now swaps that listener for one
 * of this component — WorkflowGuardPass does it — and the same `guard:` lines keep working.
 *
 * With Security the listener is deliberately left alone: those guards already reach the component,
 * `security.access.decision_manager` being an alias to it, so swapping would gain nothing and would
 * cost the trust resolver an expression may name.
 *
 * The transitions below are the same in both shapes, which is what makes the two comparable. Only
 * two things move: where the role hierarchy is declared, and who says who is asking.
 */
final class WorkflowKernel extends Kernel
{
    /**
     * ROLE_ADMIN reaches ROLE_EDITOR, which reaches ROLE_READER — the hierarchy of the standalone
     * demo, so that a guard naming ROLE_EDITOR is satisfied by an admin.
     */
    public const HIERARCHY = [
        'ROLE_ADMIN' => ['ROLE_EDITOR'],
        'ROLE_EDITOR' => ['ROLE_READER'],
    ];

    /**
     * The workflow service, aliased public so a test can drive it.
     */
    public const WORKFLOW = 'test.workflow.document';

    /**
     * The listener the guards are dispatched to, whichever class ends up behind it.
     */
    public const GUARD_LISTENER = 'test.workflow.guard_listener';

    use MicroKernelTrait;

    public function __construct(
        private readonly bool $withSecurity = false,
    ) {
        parent::__construct('test', true);
    }

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();

        if ($this->withSecurity) {
            yield new SecurityBundle();
        }

        yield new AccessControlBundle();
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
    }

    protected function configureContainer(ContainerBuilder $container, LoaderInterface $loader): void
    {
        $container->loadFromExtension('framework', [
            'secret' => 'act-workflow',
            'router' => ['utf8' => true],
            'test' => true,
            'http_method_override' => false,
            // is_valid() is served by the Validator, and an attribute constraint is only read when
            // attributes are enabled: without this the guard would answer true on a blank title and
            // measure nothing.
            'validation' => ['enabled' => true, 'enable_attributes' => true],
            'workflows' => [
                'document' => [
                    'type' => 'state_machine',
                    'marking_store' => ['type' => 'method', 'property' => 'marking'],
                    'supports' => [WorkflowDocument::class],
                    'initial_marking' => 'draft',
                    'places' => ['draft', 'in_review', 'published', 'archived'],
                    'transitions' => [
                        // Workflow's own function, which does not come from Security and is not an
                        // access question at all. It is served here by an expression language of
                        // this component's, kept apart from the one access rules speak so that a
                        // rule does not gain a Validator function by accident.
                        'submit' => [
                            'from' => 'draft',
                            'to' => 'in_review',
                            'guard' => 'is_valid(subject)',
                        ],

                        // A second transition out of the same place, guarded differently. Every
                        // guard of a workflow reaches the same listener, so a reader being able to
                        // submit while unable to discard is what tells the two apart.
                        'discard' => [
                            'from' => 'draft',
                            'to' => 'archived',
                            'guard' => "is_granted('ROLE_ADMIN')",
                        ],

                        // A role and the subject in one expression: an editor may publish, but not
                        // what they wrote themselves. `subject` and `user` are the variables an
                        // access rule sees, which is the point of reusing the expression voter
                        // rather than rebuilding them.
                        'publish' => [
                            'from' => 'in_review',
                            'to' => 'published',
                            'guard' => "is_granted('ROLE_EDITOR') and subject.author != user.getUserIdentifier()",
                        ],
                    ],
                ],
            ],
        ]);

        $this->withSecurity ? $this->configureWithSecurity($container) : $this->configureWithoutSecurity($container);

        $container->setAlias(self::WORKFLOW, 'state_machine.document')->setPublic(true);
        // Registered private and dotted by FrameworkExtension, hence the leading dot.
        $container->setAlias(self::GUARD_LISTENER, '.state_machine.document.listener.guard')->setPublic(true);
    }

    /**
     * No firewall, no token, no user provider. The hierarchy is declared on this component's own
     * key — there is no security.yaml to put it in — and the application says who is asking.
     */
    private function configureWithoutSecurity(ContainerBuilder $container): void
    {
        $container->loadFromExtension('access_control', [
            'role_hierarchy' => self::HIERARCHY,
        ]);

        $container->register(MutableRequesterProvider::class, MutableRequesterProvider::class)
            ->setPublic(true);
        $container->setAlias('access_control.requester_provider', MutableRequesterProvider::class);
    }

    /**
     * The same workflow in an application that kept Security. Nothing here is about workflows: the
     * hierarchy moves to Security's key, because declaring it on both raises, and the token storage
     * says who is asking as it always did.
     */
    private function configureWithSecurity(ContainerBuilder $container): void
    {
        $container->loadFromExtension('security', [
            'password_hashers' => [InMemoryUser::class => 'plaintext'],
            'providers' => ['main' => ['memory' => ['users' => [
                'erin' => ['password' => 'pa$$word', 'roles' => ['ROLE_EDITOR']],
            ]]]],
            'role_hierarchy' => self::HIERARCHY,
            'firewalls' => [
                'main' => ['pattern' => '^/', 'http_basic' => null, 'provider' => 'main'],
            ],
        ]);

        $container->loadFromExtension('access_control', []);
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir().'/act-workflow/'.($this->withSecurity ? 'security' : 'standalone');
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir().'/act-workflow/log';
    }

    protected function build(ContainerBuilder $container): void
    {
        $container->register('logger', NullLogger::class);
    }
}
