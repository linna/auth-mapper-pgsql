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
use Linna\Authentication\UserMapperInterface;
use Linna\DataMapper\DomainObjectInterface;
use Linna\DataMapper\MapperAbstract;
use Linna\DataMapper\NullDomainObject;
use Linna\Storage\ExtendedPDO;
use PDO;
use PDOException;
use PDOStatement;
use RuntimeException;

/**
 * Role Mapper.
 */
class RoleMapper extends MapperAbstract implements RoleMapperInterface
{
    /**
     * @var ExtendedPDO Database Connection
     */
    protected ExtendedPDO $pdo;

    /**
     * @var PermissionMapperInterface Permission Mapper
     */
    protected PermissionMapperInterface $permissionMapper;

    /**
     * @var UserMapperInterface Permission Mapper
     */
    protected UserMapperInterface $userMapper;

    /**
     * @var RoleToUserMapperInterface Role To User Mapper
     */
    protected RoleToUserMapperInterface $roleToUserMapper;

    /**
     * @var string Constant part of SELECT query
     */
    protected string $baseQuery = 'SELECT role_id AS "id", name, description, active, created, last_update AS "lastUpdate" FROM public.role';

    /**
     * Constructor.
     *
     * @param ExtendedPDO               $pdo
     * @param PermissionMapperInterface $permissionMapper
     * @param UserMapperInterface       $userMapper
     * @param RoleToUserMapperInterface $roleToUserMapper
     */
    public function __construct(
        ExtendedPDO $pdo,
        PermissionMapperInterface $permissionMapper,
        UserMapperInterface $userMapper,
        RoleToUserMapperInterface $roleToUserMapper
    ) {
        $this->pdo = $pdo;
        $this->permissionMapper = $permissionMapper;
        $this->userMapper = $userMapper;
        $this->roleToUserMapper = $roleToUserMapper;
    }

    /**
     * {@inheritdoc}
     */
    public function fetchById(int $roleId): DomainObjectInterface
    {
        $users = $this->roleToUserMapper->fetchByRoleId($roleId);
        $permissions = $this->permissionMapper->fetchByRoleId($roleId);

        $pdos = $this->pdo->prepare("{$this->baseQuery} WHERE role_id = :id");
        $pdos->bindParam(':id', $roleId, PDO::PARAM_INT);
        $pdos->execute();

        $role = $pdos->fetchObject(Role::class, [$users, $permissions]);

        unset($users, $permissions);

        if ($role instanceof Role) {
            return $role;
        }

        return new NullDomainObject();
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByName(string $roleName): DomainObjectInterface
    {
        $users = $this->roleToUserMapper->fetchByRoleName($roleName);
        $permissions = $this->permissionMapper->fetchByRoleName($roleName);

        $pdos = $this->pdo->prepare("{$this->baseQuery} WHERE name = :name");
        $pdos->bindParam(':name', $roleName, PDO::PARAM_STR);
        $pdos->execute();

        $role = $pdos->fetchObject(Role::class, [$users, $permissions]);

        unset($users, $permissions);

        if ($role instanceof Role) {
            return $role;
        }

        return new NullDomainObject();
    }

    /**
     * {@inheritdoc}
     */
    public function fetchAll(): array
    {
        $pdos = $this->pdo->prepare($this->baseQuery);
        $pdos->execute();

        return $this->roleCompositor($pdos);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchLimit(int $offset, int $rowCount): array
    {
        $pdos = $this->pdo->prepare("{$this->baseQuery} LIMIT :rowcount OFFSET :offset");
        $pdos->bindParam(':offset', $offset, PDO::PARAM_INT);
        $pdos->bindParam(':rowcount', $rowCount, PDO::PARAM_INT);
        $pdos->execute();

        return $this->roleCompositor($pdos);
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
    public function fetchByPermissionId(int $permissionId): array
    {
        $pdos = $this->pdo->prepare('
        SELECT r.role_id AS "id", r.name, r.description, r.active, r.created, r.last_update AS "lastUpdate"
        FROM public.role AS r
        INNER JOIN public.role_permission AS rp 
        ON r.role_id = rp.role_id
        WHERE rp.permission_id = :id');

        $pdos->bindParam(':id', $permissionId, PDO::PARAM_INT);
        $pdos->execute();

        return $this->roleCompositor($pdos);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByPermissionName(string $permissionName): array
    {
        $permission = $this->permissionMapper->fetchByName($permissionName);

        return $this->fetchByPermissionId($permission->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByUser(EnhancedUser $user): array
    {
        return $this->fetchByUserId($user->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByUserId(int $userId): array
    {
        $pdos = $this->pdo->prepare('
        SELECT r.role_id AS "id", r.name, r.description, r.active, r.created, r.last_update AS "lastUpdate"
        FROM public.role AS r
        INNER JOIN public.user_role AS ur 
        ON r.role_id = ur.role_id
        WHERE ur.user_id = :id');

        $pdos->bindParam(':id', $userId, PDO::PARAM_INT);
        $pdos->execute();

        return $this->roleCompositor($pdos);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByUserName(string $userName): array
    {
        $user = $this->userMapper->fetchByName($userName);

        return $this->fetchByUserId($user->getId());
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
    protected function roleCompositor(PDOStatement &$pdos): array
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
    public function grantPermission(Role &$role, Permission $permission)
    {
        $this->grantPermissionById($role, $permission->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function grantPermissionById(Role &$role, int $permissionId)
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
    public function grantPermissionByName(Role &$role, string $permissionName)
    {
        $permission = $this->permissionMapper->fetchByName($permissionName);

        $this->grantPermissionById($role, $permission->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function revokePermission(Role &$role, Permission $permission)
    {
        $this->revokePermissionById($role, $permission->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function revokePermissionById(Role &$role, int $permissionId)
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
    public function revokePermissionByName(Role &$role, string $permissionName)
    {
        $permission = $this->permissionMapper->fetchByName($permissionName);

        $this->revokePermissionById($role, $permission->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function addUser(Role &$role, EnhancedUser $user)
    {
        $this->addUserById($role, $user->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function addUserById(Role &$role, int $userId)
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
    public function addUserByName(Role &$role, string $userName)
    {
        $user = $this->userMapper->fetchByName($userName);

        $this->addUserById($role, $user->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function removeUser(Role &$role, EnhancedUser $user)
    {
        $this->removeUserById($role, $user->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function removeUserById(Role &$role, int $userId)
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
    public function removeUserByName(Role &$role, string $userName)
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
    protected function concreteInsert(DomainObjectInterface &$role)
    {
        $this->checkDomainObjectType($role);

        try {
            $pdos = $this->pdo->prepare('INSERT INTO public.role (name, description, active) VALUES (:name, :description, :active)');

            $pdos->bindParam(':name', $role->name, PDO::PARAM_STR);
            $pdos->bindParam(':description', $role->description, PDO::PARAM_STR);
            $pdos->bindParam(':active', $role->active, PDO::PARAM_BOOL);
            $pdos->execute();

            $role->setId((int) $this->pdo->lastInsertId());
        } catch (RuntimeException $e) {
            echo 'Insert not compled, ', $e->getMessage(), "\n";
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function concreteUpdate(DomainObjectInterface $role)
    {
        $this->checkDomainObjectType($role);

        $objId = $role->getId();

        try {
            $pdos = $this->pdo->prepare('UPDATE public.role SET name = :name, description = :description, active = :active WHERE (role_id = :id)');

            $pdos->bindParam(':id', $objId, PDO::PARAM_INT);
            $pdos->bindParam(':name', $role->name, PDO::PARAM_STR);
            $pdos->bindParam(':description', $role->description, PDO::PARAM_STR);
            $pdos->bindParam(':active', $role->active, PDO::PARAM_BOOL);
            $pdos->execute();
        } catch (RuntimeException $e) {
            echo 'Update not compled, ', $e->getMessage(), "\n";
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function concreteDelete(DomainObjectInterface &$role)
    {
        $this->checkDomainObjectType($role);

        $objId = $role->getId();

        try {
            $pdos = $this->pdo->prepare('DELETE FROM public.role WHERE role_id = :id');

            $pdos->bindParam(':id', $objId, PDO::PARAM_INT);
            $pdos->execute();

            $role = new NullDomainObject();
        } catch (RuntimeException $e) {
            echo 'Delete not compled, ', $e->getMessage(), "\n";
        }
    }

    /**
     * {@inheritdoc}
     */
    protected function checkDomainObjectType(DomainObjectInterface $domainObject)
    {
        if (!($domainObject instanceof Role)) {
            throw new InvalidArgumentException('Domain Object parameter must be instance of Role class');
        }
    }
}
