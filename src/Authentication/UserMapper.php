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

use InvalidArgumentException;
use Linna\Authentication\Password;
use Linna\DataMapper\DomainObjectAbstract;
use Linna\DataMapper\DomainObjectInterface;
use Linna\DataMapper\MapperAbstract;
use Linna\DataMapper\NullDomainObject;
use Linna\Storage\ExtendedPDO;
use PDO;
use RuntimeException;

/**
 * UserMapper.
 */
class UserMapper extends MapperAbstract implements UserMapperInterface
{
    /**
     * @var Password Password util for user object
     */
    protected Password $password;

    /**
     * @var ExtendedPDO Database Connection
     */
    protected ExtendedPDO $pdo;

    /**
     * @var string Constant part of SELECT query
     */
    protected string $baseQuery = 'SELECT user_id AS "id", uuid, name, email, description, password, active, created, last_update AS "lastUpdate" FROM public.user';

    /**
     * Constructor.
     *
     * @param ExtendedPDO $pdo
     * @param Password    $password
     */
    public function __construct(ExtendedPDO $pdo, Password $password)
    {
        $this->pdo = $pdo;
        $this->password = $password;
    }

    /**
     * Fetch a user by id.
     *
     * @param int $userId
     *
     * @return DomainObjectInterface
     */
    public function fetchById(int $userId): DomainObjectInterface
    {
        $pdos = $this->pdo->prepare("{$this->baseQuery} WHERE user_id = :id");

        $pdos->bindParam(':id', $userId, PDO::PARAM_INT);
        $pdos->execute();

        $result = $pdos->fetchObject(User::class, [$this->password]);

        return ($result instanceof User) ? $result : new NullDomainObject();
    }

    /**
     * Fetch a user by name.
     *
     * @param string $userName
     *
     * @return DomainObjectAbstract
     */
    public function fetchByName(string $userName): DomainObjectInterface
    {
        $pdos = $this->pdo->prepare("{$this->baseQuery} WHERE md5(name) = :name");

        $hashedUserName = \md5($userName);

        $pdos->bindParam(':name', $hashedUserName, PDO::PARAM_STR);
        $pdos->execute();

        $result = $pdos->fetchObject(User::class, [$this->password]);

        return ($result instanceof User) ? $result : new NullDomainObject();
    }

    /**
     * Fetch all users stored in data base.
     *
     * @return array
     */
    public function fetchAll(): array
    {
        $pdos = $this->pdo->prepare("{$this->baseQuery} ORDER BY name ASC");

        $pdos->execute();

        $array = $pdos->fetchAll(PDO::FETCH_CLASS, User::class, [$this->password]);

        return \array_combine(\array_column($array, 'id'), $array);
    }

    /**
     * Fetch users with limit.
     *
     * @param int $offset   Offset of the first row to return
     * @param int $rowCount Maximum number of rows to return
     *
     * @return array
     */
    public function fetchLimit(int $offset, int $rowCount): array
    {
        $pdos = $this->pdo->prepare("{$this->baseQuery} ORDER BY name ASC LIMIT :rowcount OFFSET :offset");

        $pdos->bindParam(':offset', $offset, PDO::PARAM_INT);
        $pdos->bindParam(':rowcount', $rowCount, PDO::PARAM_INT);
        $pdos->execute();

        $array = $pdos->fetchAll(PDO::FETCH_CLASS, User::class, [$this->password]);

        return \array_combine(\array_column($array, 'id'), $array);
    }

    /**
     * Create a new instance of a User.
     *
     * @return DomainObjectInterface
     */
    protected function concreteCreate(): DomainObjectInterface
    {
        return new User($this->password);
    }

    /**
     * Insert a User object to persistent storage.
     * User object passed as reference, gain the id of the persistent
     * storage record.
     *
     * @param DomainObjectInterface $user
     */
    protected function concreteInsert(DomainObjectInterface &$user)
    {
        $this->checkDomainObjectType($user);

        try {
            $pdos = $this->pdo->prepare('INSERT INTO public.user (uuid, name, email, description, password, created) VALUES (:uuid, :name, :email, :description, :password, NOW())');

            $pdos->bindParam(':uuid', $user->uuid, PDO::PARAM_STR);
            $pdos->bindParam(':name', $user->name, PDO::PARAM_STR);
            $pdos->bindParam(':email', $user->email, PDO::PARAM_STR);
            $pdos->bindParam(':description', $user->description, PDO::PARAM_STR);
            $pdos->bindParam(':password', $user->password, PDO::PARAM_STR);
            $pdos->execute();

            $user->setId((int) $this->pdo->lastInsertId());
        } catch (RuntimeException $e) {
            echo 'Insert not compled, ', $e->getMessage(), "\n";
        }
    }

    /**
     * Update a User object in persistent storage.
     *
     * @param DomainObjectInterface $user
     */
    protected function concreteUpdate(DomainObjectInterface $user)
    {
        $this->checkDomainObjectType($user);

        $objId = $user->getId();

        try {
            $pdos = $this->pdo->prepare('UPDATE public.user SET name = :name, email = :email, description = :description,  password = :password, active = :active WHERE user_id = :id');

            $pdos->bindParam(':id', $objId, PDO::PARAM_INT);
            $pdos->bindParam(':name', $user->name, PDO::PARAM_STR);
            $pdos->bindParam(':email', $user->email, PDO::PARAM_STR);
            $pdos->bindParam(':password', $user->password, PDO::PARAM_STR);
            $pdos->bindParam(':description', $user->description, PDO::PARAM_STR);
            $pdos->bindParam(':active', $user->active, PDO::PARAM_BOOL);

            $pdos->execute();
        } catch (RuntimeException $e) {
            echo 'Update not compled, ', $e->getMessage(), "\n";
        }
    }

    /**
     * Delete a User object from peristent Storage.
     * User object passed as reference, become NullDomainObject after
     * deletion.
     *
     * @param DomainObjectInterface $domainObject
     */
    protected function concreteDelete(DomainObjectInterface &$user)
    {
        $this->checkDomainObjectType($user);

        $objId = $user->getId();

        try {
            $pdos = $this->pdo->prepare('DELETE FROM public.user WHERE user_id = :id');
            $pdos->bindParam(':id', $objId, PDO::PARAM_INT);
            $pdos->execute();

            $user = new NullDomainObject();
        } catch (RuntimeException $e) {
            echo 'Delete not compled, ', $e->getMessage(), "\n";
        }
    }

    /**
     * Check for valid domain Object.
     *
     * @param DomainObjectInterface $domainObject
     *
     * @throws InvalidArgumentException if the domain object isn't of the type required by mapper
     */
    protected function checkDomainObjectType(DomainObjectInterface $domainObject)
    {
        if (!($domainObject instanceof User)) {
            throw new InvalidArgumentException('Domain Object parameter must be instance of User class');
        }
    }
}
