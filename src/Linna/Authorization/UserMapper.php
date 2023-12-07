<?php

/**
 * Linna Framework.
 *
 * @author Sebastian Rapetti <sebastian.rapetti@tim.it>
 * @copyright (c) 2020, Sebastian Rapetti
 * @license http://opensource.org/licenses/MIT MIT License
 */
declare(strict_types=1);

namespace Linna\Authorization;

use DateTimeImmutable;
use InvalidArgumentException;
use Linna\Authentication\Password;
use Linna\DataMapper\DomainObjectAbstract;
use Linna\DataMapper\DomainObjectInterface;
use Linna\DataMapper\MapperAbstract;
use Linna\DataMapper\NullDomainObject;
use Linna\Storage\ExtendedPDO;
use PDO;
use RuntimeException;
use stdClass;

/**
 * UserMapper.
 */
class UserMapper extends MapperAbstract implements UserMapperInterface
{
    protected const QUERY_BASE = 'SELECT user_id , uuid, name, email, description, password, active, created, last_update FROM public.user';

    private const EXCEPTION_MESSAGE = 'Domain Object parameter must be instance of User class';

    /** @var Password Password util for user object */
    protected static Password $password;

    /**
     * Constructor.
     *
     * @param ExtendedPDO $pdo
     * @param Password    $password
     */
    public function __construct(
        /** @var ExtendedPDO Database Connection */
        protected ExtendedPDO $pdo,

        /** @var Password Password util for user object */
        Password $passwordUtility = new Password()
    ) {
        self::$password = $passwordUtility;
    }

    /**
     * Hydrate an array of objects.
     *
     * @param array<int, stdClass> $array The array containing the resultset from database.
     *
     * @return array<int, User>
     */
    protected function hydrator(array $array): array
    {
        $tmp = [];

        foreach ($array as $value) {
            $tmp[] = new User(
                passwordUtility: self::$password,
                id:              $value->user_id,
                uuid:            $value->uuid,
                name:            $value->name,
                description:     $value->description,
                email:           $value->email,
                password:        $value->password,
                active:          (int) $value->active,
                created:         new DateTimeImmutable($value->created),
                lastUpdate:      new DateTimeImmutable($value->last_update)
            );
        }

        return $tmp;
    }

    /**
     * Hydrate an object.
     *
     * @param object $object The object containing the resultset from database.
     *
     * @return DomainObjectInterface
     */
    protected function hydratorSingle(object $object): DomainObjectInterface
    {
        return new User(
            passwordUtility: self::$password,
            id:              $object->user_id,
            uuid:            $object->uuid,
            name:            $object->name,
            description:     $object->description,
            email:           $object->email,
            password:        $object->password,
            active:          (int) $object->active,
            created:         new DateTimeImmutable($object->created),
            lastUpdate:      new DateTimeImmutable($object->last_update)
        );
    }

    /**
     * Fetch a user by id.
     *
     * @param int|string $userId
     *
     * @return DomainObjectInterface
     */
    public function fetchById(int|string $userId): DomainObjectInterface
    {
        //make query
        $stmt = $this->pdo->prepare(self::QUERY_BASE.' WHERE user_id = :id');
        $stmt->bindParam(':id', $userId, PDO::PARAM_INT);
        $stmt->execute();

        //fail fast
        if (($stdClass = $stmt->fetchObject()) === false) {
            return new NullDomainObject();
        }

        //return result
        return $this->hydratorSingle($stdClass);
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
        //handle user name
        $hashedUserName = \md5($userName);

        //make query
        $stmt = $this->pdo->prepare(self::QUERY_BASE.' WHERE md5(name) = :name');
        $stmt->bindParam(':name', $hashedUserName, PDO::PARAM_STR);
        $stmt->execute();

        //fail fast
        if (($stdClass = $stmt->fetchObject()) === false) {
            return new NullDomainObject();
        }

        //return result
        return $this->hydratorSingle($stdClass);
    }

    /**
     * Fetch all users stored in data base.
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
        return $this->hydrator($result);
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
        //make query
        $stmt = $this->pdo->prepare(self::QUERY_BASE.' ORDER BY name ASC LIMIT :rowcount OFFSET :offset');
        $stmt->bindParam(':offset', $offset, PDO::PARAM_INT);
        $stmt->bindParam(':rowcount', $rowCount, PDO::PARAM_INT);
        $stmt->execute();

        $result = $stmt->fetchAll(PDO::FETCH_CLASS, stdClass::class);

        //fail fast, returns the empty array
        if (\count($result) === 0) {
            return $result;
        }

        //return result
        return $this->hydrator($result);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByPermission(Permission $permission): array
    {
        return $this->fetchByPermissionId($permission->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByPermissionId(int|string $permissionId): array
    {
        //make query
        $stmt = $this->pdo->prepare('
        (SELECT 
            u.user_id, u.uuid, u.name, u.email, u.description, u.password, u.active, u.created, u.last_update
        FROM
            public.user AS u
                INNER JOIN
            public.user_permission AS up ON u.user_id = up.user_id
        WHERE
            up.permission_id = :id) 
        UNION 
        (SELECT 
            u.user_id, u.uuid, u.name, u.email, u.description, u.password, u.active, u.created, u.last_update
        FROM
            public.user AS u
                INNER JOIN
            public.user_role AS ur ON u.user_id = ur.user_id
                INNER JOIN
            public.role AS r ON ur.role_id = r.role_id
                INNER JOIN
            public.role_permission AS rp ON r.role_id = rp.role_id
        WHERE
            rp.permission_id = :id)');

        $stmt->bindParam(':id', $permissionId, PDO::PARAM_INT);
        $stmt->execute();

        $result = $stmt->fetchAll(PDO::FETCH_CLASS, stdClass::class);

        //fail fast, returns the empty array
        if (\count($result) === 0) {
            return $result;
        }

        //return result
        return $this->hydrator($result);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByPermissionName(string $permissionName): array
    {
        //make query
        $stmt = $this->pdo->prepare('
        (SELECT 
            u.user_id, u.uuid, u.name, u.email, u.description, u.password, u.active, u.created, u.last_update
        FROM
            public.user AS u
                INNER JOIN
            public.user_permission AS up ON u.user_id = up.user_id
                INNER JOIN
			public.permission AS p ON up.permission_id = p.permission_id
        WHERE
            p.name = :name) 
        UNION 
        (SELECT 
            u.user_id, u.uuid, u.name, u.email, u.description, u.password, u.active, u.created, u.last_update
        FROM
            public.user AS u
                INNER JOIN
            public.user_role AS ur ON u.user_id = ur.user_id
                INNER JOIN
            public.role AS r ON ur.role_id = r.role_id
                INNER JOIN
            public.role_permission AS rp ON r.role_id = rp.role_id
                INNER JOIN
			public.permission AS p ON rp.permission_id = p.permission_id
        WHERE
            p.name = :name)');

        $stmt->bindParam(':name', $permissionName, PDO::PARAM_STR);
        $stmt->execute();

        $result = $stmt->fetchAll(PDO::FETCH_CLASS, stdClass::class);

        //fail fast, returns the empty array
        if (\count($result) === 0) {
            return $result;
        }

        //return result
        return $this->hydrator($result);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByRole(Role $role): array
    {
        return $this->fetchByRoleId($role->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByRoleId(int|string $roleId): array
    {
        //make query
        $stmt = $this->pdo->prepare('
        SELECT 
            u.user_id, u.uuid, u.name, u.email, u.description, u.password, u.active, u.created, u.last_update
        FROM
            public.user AS u
                INNER JOIN
            public.user_role AS ur ON u.user_id = ur.user_id
        WHERE
            ur.role_id = :id');

        $stmt->bindParam(':id', $roleId, PDO::PARAM_INT);
        $stmt->execute();

        $result = $stmt->fetchAll(PDO::FETCH_CLASS, stdClass::class);

        //fail fast, returns the empty array
        if (\count($result) === 0) {
            return $result;
        }

        //return result
        return $this->hydrator($result);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByRoleName(string $roleName): array
    {
        //make query
        $stmt = $this->pdo->prepare('
        SELECT 
            u.user_id, u.uuid, u.name, u.email, u.description, u.password, u.active, u.created, u.last_update
        FROM
            public.user AS u
                INNER JOIN
            public.user_role AS ur ON u.user_id = ur.user_id 
                INNER JOIN
            public.role AS r ON ur.role_id = r.role_id
        WHERE
            r.name = :name');

        $stmt->bindParam(':name', $roleName, PDO::PARAM_STR);
        $stmt->execute();

        $result = $stmt->fetchAll(PDO::FETCH_CLASS, stdClass::class);

        //fail fast, returns the empty array
        if (\count($result) === 0) {
            return $result;
        }

        //return result
        return $this->hydrator($result);
    }

    /**
     * Create a new instance of a User.
     *
     * @return DomainObjectInterface
     */
    protected function concreteCreate(): DomainObjectInterface
    {
        return new User(passwordUtility: self::$password);
    }

    /**
     * Insert a User object to persistent storage.
     * User object passed as reference, gain the id of the persistent
     * storage record.
     *
     * @param DomainObjectInterface $user
     *
     * @return void
     */
    protected function concreteInsert(DomainObjectInterface &$user): void
    {
        \assert($user instanceof User, new InvalidArgumentException(self::EXCEPTION_MESSAGE));

        //get value to be passed as reference
        $created = $user->created->format(DATE_ATOM);
        $lastUpdate = $user->lastUpdate->format(DATE_ATOM);

        try {
            //make query
            $stmt = $this->pdo->prepare('INSERT INTO public.user (uuid, name, email, description, password, active, created, last_update) 
                VALUES (:uuid, :name, :email, :description, :password, :active, :created, :last_update)');
            $stmt->bindParam(':uuid', $user->uuid, PDO::PARAM_STR);
            $stmt->bindParam(':name', $user->name, PDO::PARAM_STR);
            $stmt->bindParam(':email', $user->email, PDO::PARAM_STR);
            $stmt->bindParam(':description', $user->description, PDO::PARAM_STR);
            $stmt->bindParam(':password', $user->password, PDO::PARAM_STR);
            $stmt->bindParam(':active', $user->active, PDO::PARAM_BOOL);
            $stmt->bindParam(':created', $created, PDO::PARAM_STR);
            $stmt->bindParam(':last_update', $lastUpdate, PDO::PARAM_STR);

            $stmt->execute();

            \settype($user->active, "integer");

            $user->setId((int) $this->pdo->lastInsertId());
        } catch (RuntimeException $e) {
            echo 'Insert not compled, ', $e->getMessage(), "\n";
        }
    }

    /**
     * Update a User object in persistent storage.
     *
     * @param DomainObjectInterface $user
     *
     * @return void
     */
    protected function concreteUpdate(DomainObjectInterface $user): void
    {
        \assert($user instanceof User, new InvalidArgumentException(self::EXCEPTION_MESSAGE));

        //get value to be passed as reference
        $objId = $user->getId();
        $lastUpdate = $user->lastUpdate->format(DATE_ATOM);

        try {
            //make query
            $stmt = $this->pdo->prepare('UPDATE public.user 
                SET name = :name, email = :email, description = :description,  password = :password, active = :active, last_update = :last_update 
                WHERE user_id = :id');

            $stmt->bindParam(':id', $objId, PDO::PARAM_INT);
            $stmt->bindParam(':name', $user->name, PDO::PARAM_STR);
            $stmt->bindParam(':email', $user->email, PDO::PARAM_STR);
            $stmt->bindParam(':description', $user->description, PDO::PARAM_STR);
            $stmt->bindParam(':password', $user->password, PDO::PARAM_STR);
            $stmt->bindParam(':active', $user->active, PDO::PARAM_BOOL);
            $stmt->bindParam(':last_update', $lastUpdate, PDO::PARAM_STR);

            $stmt->execute();

            \settype($user->active, "integer");

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
     *
     * @return void
     */
    protected function concreteDelete(DomainObjectInterface &$user): void
    {
        \assert($user instanceof User, new InvalidArgumentException(self::EXCEPTION_MESSAGE));

        //get value to be passed as reference
        $objId = $user->getId();

        try {
            $stmt = $this->pdo->prepare('DELETE FROM public.user WHERE user_id = :id');
            $stmt->bindParam(':id', $objId, PDO::PARAM_INT);
            $stmt->execute();

            $user = new NullDomainObject();
        } catch (RuntimeException $e) {
            echo 'Delete not compled, ', $e->getMessage(), "\n";
        }
    }
}
