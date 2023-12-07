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
 * Role Mapper.
 */
class RoleMapper extends MapperAbstract implements RoleMapperInterface
{
    protected const QUERY_BASE = 'SELECT role_id, name, description, active, created, last_update FROM public.role';

    private const EXCEPTION_MESSAGE = 'Domain Object parameter must be instance of EnhancedUser class';

    /**
     * Constructor.
     *
     * @param ExtendedPDO $pdo Valid <code>PDO</code> instace to interact with the persistent storage.
     *
     */
    public function __construct(
        /** @var ExtendedPDO Database Connection. */
        protected ExtendedPDO $pdo,
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
            $tmp[] = new Role(
                id:              $value->role_id,
                name:            $value->name,
                description:     $value->description,
                active:          (int) $value->active,
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
        return new Role(
            id:              $object->role_id,
            name:            $object->name,
            description:     $object->description,
            active:          (int) $object->active,
            created:         new DateTimeImmutable($object->created),
            lastUpdate:      new DateTimeImmutable($object->last_update),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function fetchById(int|string $roleId): DomainObjectInterface
    {
        //make query
        $stmt = $this->pdo->prepare(self::QUERY_BASE.' WHERE role_id = :id');
        $stmt->bindParam(':id', $roleId, PDO::PARAM_INT);
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
    public function fetchByName(string $roleName): DomainObjectInterface
    {
        //handle user name
        $hashedRoleName = md5($roleName);

        //make query
        $stmt = $this->pdo->prepare(self::QUERY_BASE.' WHERE md5(name) = :name');
        $stmt->bindParam(':name', $hashedRoleName, PDO::PARAM_STR);
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
        SELECT 
            r.role_id, r.name, r.description, r.active, r.created, r.last_update
        FROM
            public.role AS r
                INNER JOIN
            public.role_permission AS rp ON r.role_id = rp.role_id
        WHERE
            rp.permission_id = :id');

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
        SELECT 
            r.role_id, r.name, r.description, r.active, r.created, r.last_update
        FROM
            public.role AS r
                INNER JOIN
            public.role_permission AS rp ON r.role_id = rp.role_id
                INNER JOIN
            public.permission as p ON rp.permission_id = p.permission_id
        WHERE
            p.name = :name');

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
        SELECT 
            r.role_id, r.name, r.description, r.active, r.created, r.last_update
        FROM
            public.role AS r
                INNER JOIN
            public.user_role AS ur ON r.role_id = ur.role_id
        WHERE
            ur.user_id = :id');

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
        SELECT 
            r.role_id, r.name, r.description, r.active, r.created, r.last_update
        FROM
            public.role AS r
                INNER JOIN
            public.user_role AS ur ON r.role_id = ur.role_id
                INNER JOIN
            public.user AS u ON ur.user_id = u.user_id
        WHERE
            u.name = :name');

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
     * Role Compositor.
     * Build roles array creating every instance for roles retrived from
     * persistent storage.
     *
     * @param PDOStatement $pdos
     *
     * @return array
     */
    /*protected function roleCompositor(PDOStatement &$pdos): array
    {
        $roles = [];

        while (($role = $pdos->fetch(PDO::FETCH_OBJ)) !== false) {
            $roleId = (int) $role->id;

            $tmp = new Role(
                $this->roleToUserMapper->fetchByRoleId($roleId),
                $this->permissionMapper->fetchByRoleId($roleId)
            );

            $tmp->setId($roleId);
            $tmp->active = (int) $role->active;
            $tmp->description = $role->description;
            $tmp->name = $role->name;
            $tmp->created = $role->created;
            $tmp->lastUpdate = $role->lastUpdate;

            $roles[$roleId] =  clone $tmp;
        }

        return $roles;
    }

    /**
     * {@inheritdoc}
     */
    /*public function grantPermission(Role &$role, Permission $permission)
    {
        $this->grantPermissionById($role, $permission->getId());
    }

    /**
     * {@inheritdoc}
     */
    /* public function grantPermissionById(Role &$role, int|string $permissionId)
     {
         $roleId = $role->getId();

         try {
             $pdos = $this->pdo->prepare('INSERT INTO public.role_permission (role_id, permission_id) VALUES (:role_id, :permission_id)');

             $pdos->bindParam(':role_id', $roleId, PDO::PARAM_INT);
             $pdos->bindParam(':permission_id', $permissionId, PDO::PARAM_INT);
             $pdos->execute();

             $role = $this->fetchById((int) $roleId);
         } catch (PDOException $e) {
             //here log the error
         }
     }

     /**
      * {@inheritdoc}
      */
    /*public function grantPermissionByName(Role &$role, string $permissionName)
    {
        $permission = $this->permissionMapper->fetchByName($permissionName);

        $this->grantPermissionById($role, $permission->getId());
    }

    /**
     * {@inheritdoc}
     */
    /*public function revokePermission(Role &$role, Permission $permission)
    {
        $this->revokePermissionById($role, $permission->getId());
    }

    /**
     * {@inheritdoc}
     */
    /*public function revokePermissionById(Role &$role, int|string $permissionId)
    {
        $roleId = $role->getId();

        $pdos = $this->pdo->prepare('DELETE FROM public.role_permission WHERE role_id = :role_id AND permission_id = :permission_id');

        $pdos->bindParam(':role_id', $roleId, PDO::PARAM_INT);
        $pdos->bindParam(':permission_id', $permissionId, PDO::PARAM_INT);
        $pdos->execute();

        $role = $this->fetchById((int) $roleId);
    }

    /**
     * {@inheritdoc}
     */
    /*public function revokePermissionByName(Role &$role, string $permissionName)
    {
        $permission = $this->permissionMapper->fetchByName($permissionName);

        $this->revokePermissionById($role, $permission->getId());
    }

    /**
     * {@inheritdoc}
     */
    /*public function addUser(Role &$role, EnhancedUser $user)
    {
        $this->addUserById($role, $user->getId());
    }

    /**
     * {@inheritdoc}
     */
    /*public function addUserById(Role &$role, int|string $userId)
    {
        $roleId = $role->getId();

        try {
            $pdos = $this->pdo->prepare('INSERT INTO public.user_role (user_id, role_id) VALUES (:user_id, :role_id)');

            $pdos->bindParam(':user_id', $userId, PDO::PARAM_INT);
            $pdos->bindParam(':role_id', $roleId, PDO::PARAM_INT);
            $pdos->execute();

            $role = $this->fetchById((int) $roleId);
        } catch (PDOException $e) {
            //here log the error
        }
    }

    /**
     * {@inheritdoc}
     */
    /*public function addUserByName(Role &$role, string $userName)
    {
        $user = $this->userMapper->fetchByName($userName);

        $this->addUserById($role, $user->getId());
    }

    /**
     * {@inheritdoc}
     */
    /*public function removeUser(Role &$role, EnhancedUser $user)
    {
        $this->removeUserById($role, $user->getId());
    }

    /**
     * {@inheritdoc}
     */
    /*public function removeUserById(Role &$role, int|string $userId)
    {
        $roleId = $role->getId();

        $pdos = $this->pdo->prepare('DELETE FROM public.user_role WHERE role_id = :role_id AND user_id = :user_id');

        $pdos->bindParam(':role_id', $roleId, PDO::PARAM_INT);
        $pdos->bindParam(':user_id', $userId, PDO::PARAM_INT);
        $pdos->execute();

        $role = $this->fetchById((int) $roleId);
    }

    /**
     * {@inheritdoc}
     */
    /*public function removeUserByName(Role &$role, string $userName)
    {
        $user = $this->userMapper->fetchByName($userName);

        $this->removeUserById($role, $user->getId());
    }

    /**
     * {@inheritdoc}
     */
    protected function concreteCreate(): DomainObjectInterface
    {
        return new Role();
    }

    /**
     * {@inheritdoc}
     */
    protected function concreteInsert(DomainObjectInterface &$role): void
    {
        \assert($role instanceof Role, new InvalidArgumentException(self::EXCEPTION_MESSAGE));

        //get value to be passed as reference
        $created = $role->created->format(DATE_ATOM);
        $lastUpdate = $role->lastUpdate->format(DATE_ATOM);

        try {
            //make query
            $stmt = $this->pdo->prepare('INSERT INTO public.role (name, description, active, created, last_update) VALUES (:name, :description, :active, :created, :last_update)');

            $stmt->bindParam(':name', $role->name, PDO::PARAM_STR);
            $stmt->bindParam(':description', $role->name, PDO::PARAM_STR);
            $stmt->bindParam(':active', $role->active, PDO::PARAM_INT);
            $stmt->bindParam(':created', $created, PDO::PARAM_STR);
            $stmt->bindParam(':last_update', $lastUpdate, PDO::PARAM_STR);

            $stmt->execute();

            $role->setId((int) $this->pdo->lastInsertId());
        } catch (RuntimeException $e) {
            echo 'Insert not compled, ', $e->getMessage(), "\n";
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function concreteUpdate(DomainObjectInterface $role): void
    {
        \assert($role instanceof Role, new InvalidArgumentException(self::EXCEPTION_MESSAGE));

        //get value to be passed as reference
        $objId = $role->getId();
        $lastUpdate = $role->lastUpdate->format(DATE_ATOM);

        try {
            //make query
            $stmt = $this->pdo->prepare('UPDATE public.role SET name = :name, description = :description, active = :active, last_update = :last_update  WHERE (role_id = :id)');

            $stmt->bindParam(':id', $objId, PDO::PARAM_INT);
            $stmt->bindParam(':name', $role->name, PDO::PARAM_STR);
            $stmt->bindParam(':description', $role->description, PDO::PARAM_STR);
            $stmt->bindParam(':active', $role->active, PDO::PARAM_INT);
            $stmt->bindParam(':last_update', $lastUpdate, PDO::PARAM_STR);

            $stmt->execute();
        } catch (RuntimeException $e) {
            echo 'Update not compled, ', $e->getMessage(), "\n";
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function concreteDelete(DomainObjectInterface &$role): void
    {
        \assert($role instanceof Role, new InvalidArgumentException(self::EXCEPTION_MESSAGE));

        //get value to be passed as reference
        $objId = $role->getId();

        try {
            //make query
            $stmt = $this->pdo->prepare('DELETE FROM public.role WHERE role_id = :id');

            $stmt->bindParam(':id', $objId, PDO::PARAM_INT);
            $stmt->execute();

            $role = new NullDomainObject();
        } catch (RuntimeException $e) {
            echo 'Delete not compled, ', $e->getMessage(), "\n";
        }
    }
}
