<?php

declare(strict_types=1);

namespace App\Model;

/**
 * A plain object used as the *subject* (the resource being acted upon) of an
 * access request. It carries the username of its owner so a voter can reason
 * about it.
 */
final class Document
{
    public function __construct(
        public readonly int $id,
        public readonly string $owner,
        public readonly string $title,
        public readonly string $body,
        // "Locked" documents are frozen by compliance: the ComplianceVoter vetoes
        // any attempt to publish them, which the strategy demo relies on.
        public readonly bool $locked = false,
        /**
         * Where the document sits in the publication workflow, and the one property that is not
         * readonly: a marking store has to write it, `marking_store: { type: method, property:
         * marking }` naming it.
         *
         * The store is rebuilt per request, so a transition applied here does not outlive the
         * response. Deliberate: the page is about which transitions are *allowed*, and a marking
         * that survived would need a database this demo does not have.
         */
        public ?string $marking = 'draft',
    ) {
    }
}
