<?php

declare(strict_types=1);

namespace App\Tests\Unit;

use AccessControl\AccessRequest;
use AccessControl\Test\AccessOutcomeAssertionsTrait;
use App\Model\Document;
use App\Security\ComplianceVoter;
use App\Security\DocumentVoter;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * A voter on its own, with no container, no manager and no strategy in sight.
 *
 * The component ships the assertions for this: assertAccessGranted(), assertAccessDenied() and
 * assertAccessAbstained() take an outcome or a whole decision, so the same three read a single
 * voter here and a manager assembled from several elsewhere. They say what was expected rather
 * than comparing enum cases, which is what makes a failure legible.
 */
final class DocumentVoterTest extends TestCase
{
    use AccessOutcomeAssertionsTrait;

    public function testTheOwnerMayViewAndEdit(): void
    {
        $voter = new DocumentVoter();
        $document = $this->document(owner: 'alice');

        self::assertAccessGranted($voter->vote($this->request('alice', ['ROLE_USER'], 'VIEW', $document)));
        self::assertAccessGranted($voter->vote($this->request('alice', ['ROLE_USER'], 'EDIT', $document)));
    }

    /**
     * The distinction the whole voter exists for: reading someone else's document is an
     * administrator's privilege, writing to it is nobody's.
     */
    public function testAnAdministratorReadsEverythingAndWritesNothing(): void
    {
        $voter = new DocumentVoter();
        $document = $this->document(owner: 'alice');
        $admin = $this->request('root', ['ROLE_ADMIN'], 'VIEW', $document);

        self::assertAccessGranted($voter->vote($admin));
        self::assertAccessDenied($voter->vote($this->request('root', ['ROLE_ADMIN'], 'EDIT', $document)));
    }

    /**
     * Abstaining is not refusing. A voter that denied everything it does not understand would get
     * in every other voter's way, which is why the three-valued outcome exists at all.
     */
    public function testItAbstainsOnAnythingThatIsNotItsBusiness(): void
    {
        $voter = new DocumentVoter();

        self::assertAccessAbstained($voter->vote($this->request('alice', ['ROLE_USER'], 'VIEW', subject: null)));
        self::assertAccessAbstained($voter->vote($this->request('alice', ['ROLE_USER'], 'SOMETHING_ELSE', $this->document())));
    }

    public function testAnAnonymousRequesterIsRefusedRatherThanIgnored(): void
    {
        $voter = new DocumentVoter();

        // Refused rather than abstained on purpose: the voter understood the question perfectly
        // well, and the answer is no.
        self::assertAccessDenied($voter->vote(new AccessRequest(null, 'VIEW', $this->document())));
    }

    /**
     * The second voter on the same attribute, which is what makes the strategy observable — it
     * only ever refuses or steps aside, never grants.
     */
    public function testComplianceVetoesLockedDocumentsAndNothingElse(): void
    {
        $voter = new ComplianceVoter();

        self::assertAccessDenied($voter->vote($this->request('alice', ['ROLE_USER'], 'PUBLISH', $this->document(locked: true))));
        self::assertAccessAbstained($voter->vote($this->request('alice', ['ROLE_USER'], 'PUBLISH', $this->document(locked: false))));
    }

    private function document(string $owner = 'alice', bool $locked = false): Document
    {
        return new Document(1, $owner, 'A title', 'A body', locked: $locked);
    }

    /**
     * @param list<string> $roles
     */
    private function request(string $username, array $roles, mixed $attribute, mixed $subject): AccessRequest
    {
        $token = new UsernamePasswordToken(new InMemoryUser($username, null, $roles), 'main', $roles);

        return new AccessRequest($token, $attribute, $subject);
    }
}
