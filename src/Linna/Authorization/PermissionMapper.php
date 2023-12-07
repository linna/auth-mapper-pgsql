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

use InvalidArgumentException;
use DateTimeImmutable;
use Linna\DataMapper\DomainObjectInterface;
use Linna\DataMapper\MapperAbstract;
use Linna\DataMapper\NullDomainObject;
use Linna\Storage\ExtendedPDO;
use PDO;
use RuntimeException;
use stdClass;

/**
 * PermissionMapper.
 */
class PermissionMapper extends MapperAbstract implements PermissionMapperInterface
{
    /** @var ExtendedPDO Database Connection */
    //protected ExtendedPDO $pdo;

    /** @var string Constant part of SELECT query */
    //protected string $baseQuery = 'SELECT permission_id AS "id", name, description, last_update AS "lastUpdate" FROM public.permission';

    protected const QUERY_BASE = 'SELECT permission_id, name, description, 0 AS inherited, created, last_update FROM public.permission';

    private const EXCEPTION_MESSAGE = 'Domain Object parameter must be instance of EnhancedUser class';

    /**
     * Constructor.
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
     * @return array<int, EnhancedUser>
     */
    protected function hydrator(array $array): array
    {
        $tmp = [];

        foreach ($array as $value) {

            $tmp[] = new Permission(
                id:              $value->permission_id,
                name:            $value->name,
                description:     $value->description,
                inherited:       $value->inherited,
                created:         new DateTimeImmutable($value->created),
                lastUpdate:      new DateTimeImmutable($value->last_update),
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
        return new Permission(
            id:              $object->permission_id,
            name:            $object->name,
            description:     $object->description,
            inherited:       $object->inherited,
            created:         new DateTimeImmutable($object->created),
            lastUpdate:      new DateTimeImmutable($object->last_update),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function fetchById(int|string $permissionId): DomainObjectInterface
    {
        //make query
        $stmt = $this->pdo->prepare(self::QUERY_BASE.' WHERE permission_id = :id');
        $stmt->bindParam(':id', $permissionId, PDO::PARAM_INT);
        $stmt->execute();

        //fail fast
        if (($stdClass = $stmt->fetchObject()) === false) {
            return new NullDomainObject();
        }

        //return result
        return $this->hydratorSingle($stdClass);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByName(string $permissionName): DomainObjectInterface
    {
        //handle permission name
        $hashedPermissionName = md5($permissionName);

        //make query
        $stmt = $this->pdo->prepare(self::QUERY_BASE.' WHERE md5(name) = :name');
        $stmt->bindParam(':name', $hashedPermissionName, PDO::PARAM_STR);
        $stmt->execute();

        //fail fast
        if (($stdClass = $stmt->fetchObject()) === false) {
            return new NullDomainObject();
        }

        //return result
        return $this->hydratorSingle($stdClass);
    }

    /**
     * {@inheritdoc}
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
     * {@inheritdoc}
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
            p.permission_id, p.name, p.description, 0 AS inherited, p.created, p.last_update
        FROM
            public.permission AS p
                INNER JOIN
            public.role_permission AS rp ON rp.permission_id = p.permission_id
        WHERE
            rp.role_id = :id');

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
            p.permission_id, p.name, p.description, 0 AS inherited, p.created, p.last_update
        FROM
            public.permission AS p
                INNER JOIN
            public.role_permission AS rp ON rp.permission_id = p.permission_id
                INNER JOIN
            public.role AS r ON rp.role_id = r.role_id
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
     * {@inheritdoc}
     */
    public function fetchByUser(User $user): array
    {
        return $this->fetchByUserId($user->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByUserId(int|string $userId): array
    {
        //make query
        $stmt = $this->pdo->prepare('
        (SELECT 
            p.permission_id, p.name, p.description, 0 AS inherited, p.created, p.last_update
        FROM
            public.permission AS p
                INNER JOIN
            public.user_permission AS up ON p.permission_id = up.permission_id
        WHERE
            up.user_id = :id) 
        UNION 
        (SELECT 
            p.permission_id, p.name, p.description, r.role_id AS inherited, p.created, p.last_update
        FROM
            public.permission AS p
                INNER JOIN
            public.role_permission AS rp ON p.permission_id = rp.permission_id
                INNER JOIN
            public.role AS r ON rp.role_id = r.role_id
                INNER JOIN
            public.user_role AS ur ON r.role_id = ur.role_id
        WHERE
            ur.user_id = :id)');

        $stmt->bindParam(':id', $userId, PDO::PARAM_INT);
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
    public function fetchByUserName(string $userName): array
    {
        //make query
        $stmt = $this->pdo->prepare('
        (SELECT 
            p.permission_id, p.name, p.description, 0 AS inherited, p.created, p.last_update
        FROM
            public.permission AS p
                INNER JOIN
            public.user_permission AS up ON p.permission_id = up.permission_id
                INNER JOIN
            public.user AS u ON up.user_id = u.user_id
        WHERE
            u.name = :name)
        UNION
        (SELECT 
            p.permission_id, p.name, p.description, r.role_id AS inherited, p.created, p.last_update
        FROM
            public.permission AS p
                INNER JOIN
            public.role_permission AS rp ON p.permission_id = rp.permission_id
                INNER JOIN
            public.role AS r ON rp.role_id = r.role_id
                INNER JOIN
            public.user_role AS ur ON r.role_id = ur.role_id
                INNER JOIN
            public.user AS u ON ur.user_id = u.user_id
        WHERE
            u.name = :name)');

        $stmt->bindParam(':name', $userName, PDO::PARAM_STR);
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
    public function fetchUserPermissionHashTable(int $userId): array
    {
        //make query
        $stmt = $this->pdo->prepare('
        (SELECT 
            SHA2(CONCAT(u.user_id, ".", up.permission_id), 0) AS p_hash
        FROM
            public.user AS u
                INNER JOIN
            public.user_permission AS up ON u.user_id = up.permission_id
        WHERE
            u.user_id = :id)
        UNION
        (SELECT 
            SHA2(CONCAT(u.user_id, '.', rp.permission_id),0) AS p_hash
        FROM
            public.user AS u
                INNER JOIN
            public.user_role AS ur ON u.user_id = ur.user_id
                INNER JOIN
            public.role AS r ON ur.role_id = r.role_id
                INNER JOIN
            public.role_permission AS rp ON r.role_id = rp.role_id
        WHERE
            u.user_id = :id) 
        ORDER BY p_hash');

        $stmt->bindParam(':id', $userId, PDO::PARAM_INT);
        $stmt->execute();

        $result = $stmt->fetchAll(PDO::FETCH_COLUMN);

        //fail fast, returns the empty array
        if (\count($result) === 0) {
            return $result;
        }

        //return result
        return array_flip($result);
    }

    /**
     * {@inheritdoc}
     */
    public function permissionExistById(int|string $permissionId): bool
    {
        //make query
        $stmt = $this->pdo->prepare('SELECT permission_id FROM public.permission WHERE permission_id = :id');

        $stmt->bindParam(':id', $permissionId, PDO::PARAM_INT);
        $stmt->execute();

        return ($stmt->rowCount() > 0) ? true : false;
    }

    /**
     * {@inheritdoc}
     */
    public function permissionExistByName(string $permissionName): bool
    {
        //make query
        $stmt = $this->pdo->prepare('SELECT permission_id FROM public.permission WHERE name = :name');

        $stmt->bindParam(':name', $permissionName, PDO::PARAM_STR);
        $stmt->execute();

        return ($stmt->rowCount() > 0) ? true : false;
    }

    /**
     * {@inheritdoc}
     */
    protected function concreteCreate(): DomainObjectInterface
    {
        return new Permission();
    }

    /**
     * {@inheritdoc}
     */
    protected function concreteInsert(DomainObjectInterface &$permission): void
    {
        \assert($permission instanceof Permission, new InvalidArgumentException(self::EXCEPTION_MESSAGE));

        //get value to be passed as reference
        $created = $permission->created->format(DATE_ATOM);
        $lastUpdate = $permission->lastUpdate->format(DATE_ATOM);

        try {
            //make query
            $stmt = $this->pdo->prepare('INSERT INTO public.permission (name, description, created, last_update) VALUES (:name, :description, :created, :last_update )');

            $stmt->bindParam(':name', $permission->name, PDO::PARAM_STR);
            $stmt->bindParam(':description', $permission->description, PDO::PARAM_STR);
            $stmt->bindParam(':created', $created, PDO::PARAM_STR);
            $stmt->bindParam(':last_update', $lastUpdate, PDO::PARAM_STR);

            $stmt->execute();

            $permission->setId((int) $this->pdo->lastInsertId());
        } catch (RuntimeException $e) {
            echo 'Insert not compled, ', $e->getMessage(), "\n";
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function concreteUpdate(DomainObjectInterface $permission): void
    {
        \assert($permission instanceof Permission, new InvalidArgumentException(self::EXCEPTION_MESSAGE));

        //get value to be passed as reference
        $objId = $permission->getId();
        $lastUpdate = $permission->lastUpdate->format(DATE_ATOM);

        try {
            //make query
            $stmt = $this->pdo->prepare('UPDATE public.permission SET name = :name, description = :description, last_update = :last_update WHERE (permission_id = :id)');

            $stmt->bindParam(':id', $objId, PDO::PARAM_INT);
            $stmt->bindParam(':name', $permission->name, PDO::PARAM_STR);
            $stmt->bindParam(':description', $permission->description, PDO::PARAM_STR);
            $stmt->bindParam(':last_update', $lastUpdate, PDO::PARAM_STR);

            $stmt->execute();
        } catch (RuntimeException $e) {
            echo 'Update not compled, ', $e->getMessage(), "\n";
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function concreteDelete(DomainObjectInterface &$permission): void
    {
        \assert($permission instanceof Permission, new InvalidArgumentException(self::EXCEPTION_MESSAGE));

        //get value to be passed as reference
        $objId = $permission->getId();

        try {
            //make query
            $stmt = $this->pdo->prepare('DELETE FROM public.permission WHERE permission_id = :id');

            $stmt->bindParam(':id', $objId, PDO::PARAM_INT);
            $stmt->execute();

            $permission = new NullDomainObject();
        } catch (RuntimeException $e) {
            echo 'Delete not compled, ', $e->getMessage(), "\n";
        }
    }
}
