<?php

/**
 * Linna Framework.
 *
 * @author Sebastian Rapetti <sebastian.rapetti@tim.it>
 * @copyright (c) 2020, Sebastian Rapetti
 * @license http://opensource.org/licenses/MIT MIT License
 */
declare(strict_types=1);

namespace Linna\Authentication;

use DateTimeImmutable;
use InvalidArgumentException;
use Linna\DataMapper\DomainObjectInterface;
use Linna\DataMapper\MapperAbstract;
use Linna\DataMapper\NullDomainObject;
use Linna\Storage\ExtendedPDO;
use PDO;
use RuntimeException;
use stdClass;

/**
 * EnhancedAuthenticationMapper.
 */
class EnhancedAuthenticationMapper extends MapperAbstract implements EnhancedAuthenticationMapperInterface
{
    /** @var ExtendedPDO Database Connection */
    //protected ExtendedPDO $pdo;

    /** @var string Constant part of SELECT query */
    //protected string $baseQuery = 'SELECT login_attempt_id AS "id", user_name AS "userName", session_id AS "sessionId", ip as "ipAddress", date_time AS "when", created, last_update AS lastUpdate FROM public.login_attempt';

    private const QUERY_BASE = 'SELECT login_attempt_id, user_name, session_id, ip, date_time, created, last_update FROM public.login_attempt';

    private const EXCEPTION_MESSAGE = 'Domain Object parameter must be instance of LoginAttempt class';

    /**
     * Class Constructor.
     *
     * @param ExtendedPDO $pdo
     */
    public function __construct(
        /** @var ExtendedPDO Database Connection */
        protected ExtendedPDO $pdo
    ) {
    }

    /**
     * Hydrate an array of objects.
     *
     * @param array<int, stdClass> $array The array containing the resultset from database.
     *
     * @return array<int, LoginAttempt>
     */
    private static function hydrator(array $array): array
    {
        $tmp = [];

        foreach ($array as $value) {
            $tmp[] = new LoginAttempt(
                id:         $value->login_attempt_id,
                userName:   $value->user_name,
                sessionId:  $value->session_id,
                ipAddress:  $value->ip,
                when:       new DateTimeImmutable($value->date_time),
                created:    new DateTimeImmutable($value->created),
                lastUpdate: new DateTimeImmutable($value->last_update)
            );
        }

        return $tmp;
    }

    /**
     * Fetch a login attempt by id.
     *
     * @param int|string $loginAttemptId
     *
     * @return DomainObjectInterface
     */
    public function fetchById(int|string $loginAttemptId): DomainObjectInterface
    {
        //make query
        $stmt = $this->pdo->prepare(self::QUERY_BASE.' WHERE login_attempt_id = :id');
        $stmt->bindParam(':id', $loginAttemptId, PDO::PARAM_INT);
        $stmt->execute();

        //fail fast
        if (($stdClass = $stmt->fetchObject()) === false) {
            return new NullDomainObject();
        }

        //return result
        return new LoginAttempt(
            id:         $stdClass->login_attempt_id,
            userName:   $stdClass->user_name,
            sessionId:  $stdClass->session_id,
            ipAddress:  $stdClass->ip,
            when:       new DateTimeImmutable($stdClass->date_time),
            created:    new DateTimeImmutable($stdClass->created),
            lastUpdate: new DateTimeImmutable($stdClass->last_update)
        );
    }

    /**
     * Fetch all login attempts stored in data base.
     *
     * @return array
     */
    public function fetchAll(): array
    {
        //make query
        $stmt = $this->pdo->prepare(self::QUERY_BASE);
        $stmt->execute();

        $result = $stmt->fetchAll(PDO::FETCH_CLASS, stdClass::class);

        //fail fast, returns the empty array
        if (\count($result) === 0) {
            return $result;
        }

        //return result
        return self::hydrator($result);
    }

    /**
     * Fetch login attempt with limit.
     *
     * @param int $offset   Offset of the first row to return
     * @param int $rowCount Maximum number of rows to return
     *
     * @return array
     */
    public function fetchLimit(int $offset, int $rowCount): array
    {
        //make query
        $stmt = $this->pdo->prepare(self::QUERY_BASE.' ORDER BY date_time ASC LIMIT :rowcount OFFSET :offset');
        $stmt->bindParam(':offset', $offset, PDO::PARAM_INT);
        $stmt->bindParam(':rowcount', $rowCount, PDO::PARAM_INT);
        $stmt->execute();

        $result = $stmt->fetchAll(PDO::FETCH_CLASS, stdClass::class);

        //fail fast, returns the empty array
        if (\count($result) === 0) {
            return $result;
        }

        //return result
        return self::hydrator($result);
    }

    /**
     * Return how many login attempts did with the same user in specified time.
     *
     * @param string $userName      User name
     * @param int    $timeInSeconds Attempts in the last specified seconds
     *
     * @return int
     */
    public function fetchAttemptsWithSameUser(string $userName, int $timeInSeconds): int
    {
        //handle time
        $time = \date(DATE_ATOM, \time() - $timeInSeconds);

        //make query
        $stmt = $this->pdo->prepare('SELECT count(user_name) as attempts FROM public.login_attempt WHERE user_name = :user_name AND date_time > :time');
        $stmt->bindParam(':user_name', $userName, PDO::PARAM_STR);
        $stmt->bindParam(':time', $time, PDO::PARAM_STR);
        $stmt->execute();

        //return result
        return (int) $stmt->fetch(PDO::FETCH_LAZY)->attempts;
    }

    /**
     * Return how many login attempts did with the same session in specified time.
     *
     * @param string $sessionId     Session id
     * @param int    $timeInSeconds Attempts in the last specified seconds
     *
     * @return int
     */
    public function fetchAttemptsWithSameSession(string $sessionId, int $timeInSeconds): int
    {
        //handle time
        $time = \date(DATE_ATOM, \time() - $timeInSeconds);

        //make query
        $stmt = $this->pdo->prepare('SELECT count(session_id) as attempts FROM public.login_attempt WHERE session_id = :session_id AND date_time > :time');
        $stmt->bindParam(':session_id', $sessionId, PDO::PARAM_STR);
        $stmt->bindParam(':time', $time, PDO::PARAM_STR);
        $stmt->execute();

        //return result
        return (int) $stmt->fetch(PDO::FETCH_LAZY)->attempts;
    }

    /**
     * Return how many login attempts did with the same session in specified time.
     *
     * @param string $ipAddress     Ip address
     * @param int    $timeInSeconds Attempts in the last specified seconds
     *
     * @return int
     */
    public function fetchAttemptsWithSameIp(string $ipAddress, int $timeInSeconds): int
    {
        //handle time
        $time = \date(DATE_ATOM, \time() - $timeInSeconds);

        //make query
        $stmt = $this->pdo->prepare('SELECT count(ip) as attempts FROM public.login_attempt WHERE ip = :ip AND date_time > :time');
        $stmt->bindParam(':ip', $ipAddress, PDO::PARAM_STR);
        $stmt->bindParam(':time', $time, PDO::PARAM_STR);
        $stmt->execute();

        //return result
        return (int) $stmt->fetch(PDO::FETCH_LAZY)->attempts;
    }

    /**
     * Remove old login attempts.
     *
     * @param int $timeInSeconds
     *
     * @return bool
     */
    public function deleteOldLoginAttempts(int $timeInSeconds): bool
    {
        //handle time
        $time = \date(DATE_ATOM, \time() - $timeInSeconds);

        //make query
        $stmt = $this->pdo->prepare('DELETE FROM public.login_attempt WHERE date_time < :time');
        $stmt->bindParam(':time', $time, PDO::PARAM_STR);
        $stmt->execute();

        return true;
    }

    /**
     * Create a new instance of a LoginAttempt.
     *
     * @return DomainObjectInterface
     */
    protected function concreteCreate(): DomainObjectInterface
    {
        return new LoginAttempt();
    }

    /**
     * Insert a LoginAttempt object to persistent storage.
     * User object passed as reference, gain the id of the persistent
     * storage record.
     *
     * @param DomainObjectInterface $loginAttempt
     *
     * @return void
     */
    protected function concreteInsert(DomainObjectInterface &$loginAttempt): void
    {
        \assert($loginAttempt instanceof LoginAttempt, new InvalidArgumentException(self::EXCEPTION_MESSAGE));

        //get values to be passed as reference
        $dateTime = $loginAttempt->when->format(DATE_ATOM);
        $created = $loginAttempt->created->format(DATE_ATOM);
        $lastUpdate = $loginAttempt->lastUpdate->format(DATE_ATOM);

        try {
            //make query
            $stmt = $this->pdo->prepare('INSERT INTO public.login_attempt (user_name, session_id, ip, date_time, created, last_update) 
                VALUES (:user_name, :session_id, :ip, :date_time, :created, :last_update)');
            $stmt->bindParam(':user_name', $loginAttempt->userName, PDO::PARAM_STR);
            $stmt->bindParam(':session_id', $loginAttempt->sessionId, PDO::PARAM_STR);
            $stmt->bindParam(':ip', $loginAttempt->ipAddress, PDO::PARAM_STR);
            $stmt->bindParam(':date_time', $dateTime, PDO::PARAM_STR);
            $stmt->bindParam(':created', $created, PDO::PARAM_STR);
            $stmt->bindParam(':last_update', $lastUpdate, PDO::PARAM_STR);

            $stmt->execute();

            //update current object
            $loginAttempt->setId((int) $this->pdo->lastInsertId());
        } catch (RuntimeException $e) {
            echo 'Insert not compled, ', $e->getMessage(), "\n";
        }

    }

    /**
     * Update a LoginAttempt object in persistent storage.
     *
     * @param DomainObjectInterface $loginAttempt
     *
     * @return void
     */
    protected function concreteUpdate(DomainObjectInterface $loginAttempt): void
    {
        throw new RuntimeException('LoginAttempt class instance does not implement updates');
    }

    /**
     * Delete a LoginAttempt object from persistent Storage.
     * User object passed as reference, become NullDomainObject after
     * deletion.
     *
     * @param DomainObjectInterface $domainObject
     *
     * @return void
     */
    protected function concreteDelete(DomainObjectInterface &$loginAttempt): void
    {
        \assert($loginAttempt instanceof LoginAttempt, new InvalidArgumentException(self::EXCEPTION_MESSAGE));

        $objId = $loginAttempt->getId();

        try {
            //make query
            $stmt = $this->pdo->prepare('DELETE FROM public.login_attempt WHERE login_attempt_id = :id');
            $stmt->bindParam(':id', $objId, PDO::PARAM_INT);
            $stmt->execute();

            //update current object
            $loginAttempt = new NullDomainObject();
        } catch (RuntimeException $e) {
            echo 'Delete not compled, ', $e->getMessage(), "\n";
        }
    }
}
