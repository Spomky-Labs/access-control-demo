<?php

declare(strict_types=1);

namespace App\Security\Attribute;

use AccessControl\Attribute\AccessPolicyInterface;
use AccessControl\Attribute\CompositeAccessPolicyInterface;

/**
 * A composite policy of the application's own: whatever it wraps applies during business hours,
 * and outside them nothing does.
 *
 * The component ships three composites — All, AtLeastOneOf and When — and this is deliberately
 * none of them. When comes closest and behaves the other way round: its condition failing makes it
 * *abstain*, so the policy steps aside and something else may still grant. A window outside which
 * nobody passes has to refuse instead, or closing it would be a way of opening it.
 *
 * Implementing CompositeAccessPolicyInterface is what makes the nested policies visible to the
 * evaluator; a handler that claims this attribute is the other half (DuringBusinessHoursHandler).
 */
#[\Attribute(\Attribute::IS_REPEATABLE | \Attribute::TARGET_CLASS | \Attribute::TARGET_METHOD)]
final readonly class DuringBusinessHours implements CompositeAccessPolicyInterface
{
    /**
     * @param list<AccessPolicyInterface> $accessPolicies the policies that apply inside the window
     * @param int                         $from           first hour of the window, inclusive
     * @param int                         $to             first hour outside it
     */
    public function __construct(
        public array $accessPolicies,
        public int $from = 9,
        public int $to = 18,
        public ?string $message = null,
    ) {
    }
}
