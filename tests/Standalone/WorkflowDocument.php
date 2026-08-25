<?php

declare(strict_types=1);

namespace App\Tests\Standalone;

use Symfony\Component\Validator\Constraints\NotBlank;

/**
 * The subject a guarded transition is asked about.
 *
 * It carries an author, so that a guard can compare it with whoever is asking, and a title left
 * blank on purpose, so that `is_valid(subject)` has something to refuse.
 */
final class WorkflowDocument
{
    public ?string $marking = null;

    public function __construct(
        public string $author,
        #[NotBlank]
        public ?string $title = null,
    ) {
    }
}
