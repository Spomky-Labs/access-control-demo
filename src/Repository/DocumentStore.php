<?php

declare(strict_types=1);

namespace App\Repository;

use App\Model\Document;

/**
 * A tiny in-memory catalogue of documents, one per demo account, so the
 * DocumentVoter has something to decide about.
 */
final class DocumentStore
{
    /**
     * @var array<int, Document>
     */
    private array $documents;

    public function __construct()
    {
        // Each one starts in a different place of the publication workflow, so the guarded
        // transitions of /documents/{id}/workflow are not all the same question.
        $this->documents = [
            1 => new Document(1, 'user', 'User note', 'A private note owned by "user".', locked: true, marking: 'draft'),
            2 => new Document(2, 'manager', 'Manager memo', 'A memo owned by "manager".', marking: 'in_review'),
            // Locked *and* in review: the one place where the compliance veto and the owner's
            // grant meet, so the strategy behind a guard becomes observable.
            3 => new Document(3, 'admin', 'Admin log', 'An operations log owned by "admin".', locked: true, marking: 'in_review'),
            // Already published, so `retract` — the four-eyes transition — is within reach of
            // somebody other than its owner.
            4 => new Document(4, 'manager', 'Release notes', 'Published notes owned by "manager".', marking: 'published'),
        ];
    }

    public function find(int $id): ?Document
    {
        return $this->documents[$id] ?? null;
    }

    /**
     * @return list<Document>
     */
    public function all(): array
    {
        return array_values($this->documents);
    }
}
