<?php

declare(strict_types=1);

namespace App\Service;

/**
 * The map of this application, in one place.
 *
 * The demo grew a page at a time and the links grew with it: the home page listed everything, the
 * playground listed some of it again, and the two drifted apart. So the order lives here now — the
 * navigation, the home page and the section pages all read this, and a page added to a section
 * appears in the three of them at once.
 *
 * The sections are the questions the component answers, in the order they come up:
 *
 *   1. where a decision is applied,
 *   2. how the verdict is reached,
 *   3. who is asking,
 *   4. what can be seen afterwards.
 *
 * `owns` is what the navigation highlights on: every route of a section, including the leaf pages
 * that are not listed as entries of their own.
 */
final class Catalogue
{
    /**
     * @var array<string, array{
     *     route: string,
     *     label: string,
     *     lead: string,
     *     entries: list<array{title: string, route: string, params?: array<string, mixed>, what: string, needs: string}>,
     *     notes?: list<array{title: string, body: string}>,
     *     owns: list<string>,
     * }>
     */
    public const array SECTIONS = [
        'guards' => [
            'route' => 'app_guards',
            'label' => 'Guards',
            'lead' => 'Where a decision is applied — the five places this application is asked before anything else runs. Every one of them reaches the same voters.',
            'entries' => [
                [
                    'title' => 'An attribute on a controller',
                    'route' => 'app_dashboard',
                    'what' => 'The plainest form: one <code>#[AccessPolicy]</code>, one role, and the action never runs if it refuses.',
                    'needs' => 'any signed-in account',
                ],
                [
                    'title' => 'An attribute on the class',
                    'route' => 'app_admin',
                    'what' => 'Guards every action at once. <code>/admin/reports</code> stacks a second policy on top, and both must pass.',
                    'needs' => 'admin',
                ],
                [
                    'title' => 'A policy about a subject',
                    'route' => 'app_documents',
                    'what' => '<code>#[Argument]</code> hands the resolved <code>Document</code> to the voter, so the verdict depends on <em>which</em> document — not only on the roles held.',
                    'needs' => 'any signed-in account',
                ],
                [
                    'title' => 'Rules in configuration',
                    'route' => 'app_zone',
                    'what' => 'Path, method, IP, expression and HTTPS channel, with the same matchers <code>security.access_control</code> uses. <code>ZoneController</code> carries no attribute at all.',
                    'needs' => 'varies by rule',
                ],
                [
                    'title' => 'A workflow guard',
                    'route' => 'app_document_workflow',
                    'params' => ['id' => 1],
                    'what' => 'The <code>guard:</code> expressions of a state machine, answered by <code>DocumentVoter</code> and <code>ComplianceVoter</code> without either knowing it.',
                    'needs' => 'VIEW on the document',
                ],
            ],
            'notes' => [
                [
                    'title' => 'And on the console',
                    'body' => 'Commands carry the very same attributes. There is no logged-in user there, so <code>--as</code> stands in a service identity: <code>app:report:generate --as=admin</code> passes, <code>--as=user</code> does not. A denial exits <code>113</code> — except for the two commands <code>DeniedExitCodeListener</code> gives <code>77</code> to, because an exit status belongs to the scripts around a command rather than to the rule that refused.',
                ],
            ],
            'owns' => [
                'app_guards', 'app_dashboard', 'app_admin', 'app_admin_reports',
                'app_documents', 'app_document_show', 'app_document_edit',
                'app_document_workflow', 'app_document_transition',
                'app_zone', 'app_zone_members', 'app_zone_staff', 'app_zone_admin',
                'app_zone_local', 'app_zone_secure', 'app_zone_api',
            ],
        ],

        'decisions' => [
            'route' => 'app_decisions',
            'label' => 'Decisions',
            'lead' => 'How the verdict is reached once the question is asked — which voters answer, and what is made of their disagreement.',
            'entries' => [
                [
                    'title' => 'Five combining algorithms',
                    'route' => 'app_strategies',
                    'what' => 'One request decided five ways. The fifth is this application\'s own <code>TwoKeyStrategy</code>, a strategy for no other reason than implementing the interface.',
                    'needs' => 'any signed-in account',
                ],
                [
                    'title' => 'The same request, two algorithms',
                    'route' => 'app_document_publish',
                    'params' => ['id' => 3],
                    'what' => 'Document&nbsp;#3 is locked, so its owner grants and compliance refuses. Under <code>permit_overrides</code> it publishes; <a href="/documents/3/publish-strict">under <code>deny_overrides</code></a> it does not.',
                    'needs' => 'admin',
                ],
                [
                    'title' => 'Policy shapes',
                    'route' => 'app_policies',
                    'what' => 'What a policy can be beyond a plain attribute: a composite the component does not ship, <code>All</code>, and what a manager makes of everybody abstaining.',
                    'needs' => 'nobody — the index is public',
                ],
                [
                    'title' => 'Either of two policies',
                    'route' => 'app_playground_either',
                    'what' => '<code>#[AtLeastOneOf]</code>, the mirror of <code>All</code>: one nested policy granting is enough.',
                    'needs' => 'manager or admin',
                ],
                [
                    'title' => 'One expression, four variables',
                    'route' => 'app_document_manage',
                    'params' => ['id' => 2],
                    'what' => 'Authentication state, roles, the user and the subject in a single rule, evaluated by the <code>ExpressionVoter</code>.',
                    'needs' => 'admin, or the owner if a manager',
                ],
                [
                    'title' => 'A closure as attribute',
                    'route' => 'app_playground_closure',
                    'what' => 'The <code>ClosureVoter</code>. PHP forbids closures in attribute arguments, so this one is only reachable programmatically.',
                    'needs' => 'any signed-in account',
                ],
            ],
            'owns' => [
                'app_decisions', 'app_strategies', 'app_policies',
                'app_policy_business_hours', 'app_policy_both',
                'app_policy_abstain', 'app_policy_abstain_strict',
                'app_playground_either', 'app_playground_closure',
                'app_document_publish', 'app_document_publish_strict', 'app_document_manage',
            ],
        ],

        'requesters' => [
            'route' => 'app_requesters',
            'label' => 'Requesters',
            'lead' => 'Who is asking — and, when somebody is asking on somebody else\'s behalf, which of the two a rule means.',
            'entries' => [
                [
                    'title' => 'Switching users',
                    'route' => 'app_playground',
                    'what' => 'The <code>impersonation_*</code> Twig helpers, which the bundle keeps delegating to Security while taking <code>is_granted()</code> over.',
                    'needs' => 'ROLE_ALLOWED_TO_SWITCH to switch in, anyone to read',
                ],
                [
                    'title' => 'While impersonating',
                    'route' => 'app_playground_impersonation',
                    'what' => 'Guarded by <code>IS_IMPERSONATOR</code>, granted exactly while a <code>SwitchUserToken</code> is in play and at no other time.',
                    'needs' => 'an impersonated session',
                ],
                [
                    'title' => 'Acting on behalf',
                    'route' => 'app_playground_on_behalf',
                    'what' => 'Delegation the component\'s own way (RFC&nbsp;8693): a session keeps the customer\'s roles, and the app still knows an admin is behind it. No firewall involved.',
                    'needs' => 'nobody — decided for explicit requesters',
                ],
                [
                    'title' => 'The circumstances of the call',
                    'route' => 'app_policy_entry_point',
                    'what' => 'The access environment, filled by whoever let the call in. One attribute means "over HTTP" here and "on this console" in <code>app:entry-point:check</code>.',
                    'needs' => 'a loopback address',
                ],
            ],
            'owns' => [
                'app_requesters', 'app_playground', 'app_playground_impersonation',
                'app_playground_on_behalf', 'app_policy_entry_point',
            ],
        ],

        'reasons' => [
            'route' => 'app_reasons',
            'label' => 'Reasons',
            'lead' => 'What can be seen afterwards. A refusal reaches a requester as a bare 403 on purpose — these are the places the reason behind it is legible.',
            'entries' => [
                [
                    'title' => 'Verdicts and their reasons',
                    'route' => 'app_permissions',
                    'what' => 'The programmatic path, which hands back the whole decision rather than a yes or no — and the two Twig vocabularies side by side.',
                    'needs' => 'any signed-in account',
                ],
                [
                    'title' => 'Deciding for someone else',
                    'route' => 'app_permissions_preview',
                    'what' => '<code>is_granted_for_user()</code> across every account, with the reason each one gets. Naming its own requester is native to the component.',
                    'needs' => 'admin',
                ],
                [
                    'title' => 'The audit trail',
                    'route' => 'app_policy_audit',
                    'what' => 'Built from the three events the component dispatches, including the decisions a voter asked for while answering another one.',
                    'needs' => 'any signed-in account',
                ],
            ],
            'notes' => [
                [
                    'title' => 'And the profiler',
                    'body' => 'The <strong>Access Control</strong> panel shows the same trail for any request, with the voters, the strategy and what the bridge took over. Console commands get one too: add <code>--profile -v</code> and follow the token it prints.',
                ],
            ],
            'owns' => ['app_reasons', 'app_permissions', 'app_permissions_preview', 'app_policy_audit'],
        ],
    ];

    /**
     * The section a route belongs to, so a page can show where it sits without saying so itself.
     *
     * @return array{id: string, route: string, label: string, lead: string, entries: list<array<string, mixed>>, notes?: list<array{title: string, body: string}>, owns: list<string>}|null
     */
    public static function sectionOf(?string $route): ?array
    {
        if (null === $route) {
            return null;
        }

        foreach (self::SECTIONS as $id => $section) {
            if (\in_array($route, $section['owns'], true)) {
                return ['id' => $id, ...$section];
            }
        }

        return null;
    }
}
