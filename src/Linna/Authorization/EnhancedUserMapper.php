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
use Linna\Authentication\Password;
use Linna\Authentication\User;
use Linna\Authentication\UserMapper;
use Linna\Authorization\PermissionMapperInterface;
use Linna\Authorization\RoleToUserMapperInterface;
use Linna\DataMapper\DomainObjectInterface;
use Linna\DataMapper\NullDomainObject;
use Linna\Storage\ExtendedPDO;
use PDO;
use PDOException;
use PDOStatement;

/**
 * EnhancedUserMapper.
 */
class EnhancedUserMapper extends UserMapper implements EnhancedUserMapperInterface
{
    /**
     * @var PermissionMapperInterface Permission Mapper
     */
    protected PermissionMapperInterface $permissionMapper;

    /**
     * @var RoleToUserMapperInterface Role to user Mapper
     */
    protected RoleToUserMapperInterface $roleToUserMapper;

    /**
     * Class Constructor.
     *
     * @param ExtendedPDO               $pdo
     * @param Password                  $password
     * @param PermissionMapperInterface $permissionMapper
     * @param RoleToUserMapperInterface $roleToUserMapper
     */
    public function __construct(
        ExtendedPDO $pdo,
        Password $password,
        PermissionMapperInterface $permissionMapper,
        RoleToUserMapperInterface $roleToUserMapper
    ) {
        parent::__construct($pdo, $password);

        $this->permissionMapper = $permissionMapper;
        $this->roleToUserMapper = $roleToUserMapper;
    }

    /**
     * {@inheritdoc}
     */
    public function fetchById(string|int $userId): DomainObjectInterface
    {
        $roles = $this->roleToUserMapper->fetchByUserId($userId);
        $permissions = $this->permissionMapper->fetchByUserId($userId);

        $pdos = $this->pdo->prepare("{$this->baseQuery} WHERE user_id = :id");
        $pdos->bindParam(':id', $userId, PDO::PARAM_INT);
        $pdos->execute();

        $user = $pdos->fetchObject(EnhancedUser::class, [$this->password, $roles, $permissions]);

        unset($roles, $permissions);

        if ($user instanceof EnhancedUser) {
            return $user;
        }

        return new NullDomainObject();
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByName(string $userName): DomainObjectInterface
    {
        $user = parent::fetchByName($userName);

        if ($user instanceof User) {
            return $this->fetchById($user->getId());
        }

        return new NullDomainObject();
    }

    /**
     * {@inheritdoc}
     */
    public function fetchAll(): array
    {
        $pdos = $this->pdo->prepare("{$this->baseQuery} ORDER BY name ASC");
        $pdos->execute();

        return $this->EnhancedUserCompositor($pdos);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchLimit(int $offset, int $rowCount): array
    {
        $pdos = $this->pdo->prepare("{$this->baseQuery} ORDER BY name ASC LIMIT :rowcount OFFSET :offset");

        $pdos->bindParam(':offset', $offset, PDO::PARAM_INT);
        $pdos->bindParam(':rowcount', $rowCount, PDO::PARAM_INT);
        $pdos->execute();

        return $this->EnhancedUserCompositor($pdos);
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
    public function fetchByPermissionId(string|int $permissionId): array
    {
        $pdos = $this->pdo->prepare('
        (SELECT u.user_id AS "id", u.uuid, u.name, u.email, u.description, 
        u.password, u.active, u.created, u.last_update AS "lastUpdate" 
        FROM public.user AS u
        INNER JOIN public.user_permission AS up
        ON u.user_id = up.user_id
        WHERE up.permission_id = :id)
        UNION
        (SELECT u.user_id AS "id", u.uuid, u.name, u.email, u.description, 
        u.password, u.active, u.created, u.last_update AS "lastUpdate" 
        FROM public.user AS u
        INNER JOIN public.user_role AS ur ON u.user_id = ur.user_id
        INNER JOIN public.role AS r ON ur.role_id = r.role_id
        INNER JOIN public.role_permission AS rp ON r.role_id = rp.role_id
        WHERE rp.permission_id = :id)');

        $pdos->bindParam(':id', $permissionId, PDO::PARAM_INT);
        $pdos->execute();

        return $this->EnhancedUserCompositor($pdos);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByPermissionName(string $permissionName): array
    {
        $permission = $this->permissionMapper->fetchByName($permissionName);

        return $this->fetchByPermissionId((int) $permission->getId());
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
    public function fetchByRoleId(string|int $roleId): array
    {
        $pdos = $this->pdo->prepare('
        SELECT u.user_id AS "id", u.uuid, u.name, u.email, u.description, 
        u.password, u.active, u.created, u.last_update AS "lastUpdate"
        FROM public.user AS u
        INNER JOIN public.user_role AS ur 
        ON u.user_id = ur.user_id
        WHERE ur.role_id = :id');

        $pdos->bindParam(':id', $roleId, PDO::PARAM_INT);
        $pdos->execute();

        return $this->EnhancedUserCompositor($pdos);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByRoleName(string $roleName): array
    {
        $pdos = $this->pdo->prepare('
        SELECT u.user_id AS "id", u.uuid, u.name, u.email, u.description, 
        u.password, u.active, u.created, u.last_update AS "lastUpdate"
        FROM public.user AS u
        INNER JOIN public.user_role AS ur 
        ON u.user_id = ur.user_id
        INNER JOIN public.role AS r 
        ON ur.role_id = r.role_id
	WHERE r.name = :name');

        $pdos->bindParam(':name', $roleName, PDO::PARAM_STR);
        $pdos->execute();

        return $this->EnhancedUserCompositor($pdos);
    }

    /**
     * EnhancedUser Compositor.
     * Build users array creating every instance for users retrived from
     * persistent storage.
     *
     * @param PDOStatement $pdos
     *
     * @return array
     */
    protected function EnhancedUserCompositor(PDOStatement &$pdos): array
    {
        $users = [];

        while (($user = $pdos->fetch(PDO::FETCH_OBJ)) !== false) {
            $userId = (int) $user->id;

            $tmp = new EnhancedUser(
                $this->password,
                $this->roleToUserMapper->fetchByUserId($userId),
                $this->permissionMapper->fetchByUserId($userId)
            );

            $tmp->setId($userId);
            $tmp->uuid = $user->uuid;
            $tmp->name = $user->name;
            $tmp->description = $user->description;
            $tmp->email = $user->email;
            $tmp->password = $user->password;
            $tmp->active = (int) $user->active;
            $tmp->created = $user->created;
            $tmp->lastUpdate = $user->lastUpdate;

            $users[$userId] = clone $tmp;
        }

        return $users;
    }

    /**
     * {@inheritdoc}
     */
    public function grantPermission(EnhancedUser &$user, Permission $permission)
    {
        $this->grantPermissionById($user, $permission->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function grantPermissionById(EnhancedUser &$user, string|int $permissionId)
    {
        $userId = $user->getId();

        try {
            $pdos = $this->pdo->prepare('INSERT INTO public.user_permission (user_id, permission_id) VALUES (:user_id, :permission_id)');

            $pdos->bindParam(':user_id', $userId, PDO::PARAM_INT);
            $pdos->bindParam(':permission_id', $permissionId, PDO::PARAM_INT);
            $pdos->execute();

            $user = $this->fetchById((int) $userId);
        } catch (PDOException $e) {
            //here log the error
        }
    }

    /**
     * {@inheritdoc}
     */
    public function grantPermissionByName(EnhancedUser &$user, string $permissionName)
    {
        $permission = $this->permissionMapper->fetchByName($permissionName);

        $this->grantPermissionById($user, $permission->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function revokePermission(EnhancedUser &$user, Permission $permission)
    {
        $this->revokePermissionById($user, $permission->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function revokePermissionById(EnhancedUser &$user, string|int $permissionId)
    {
        $userId = $user->getId();

        $pdos = $this->pdo->prepare('DELETE FROM public.user_permission WHERE user_id = :user_id AND permission_id = :permission_id');

        $pdos->bindParam(':user_id', $userId, PDO::PARAM_INT);
        $pdos->bindParam(':permission_id', $permissionId, PDO::PARAM_INT);
        $pdos->execute();

        $user = $this->fetchById((int) $userId);
    }

    /**
     * {@inheritdoc}
     */
    public function revokePermissionByName(EnhancedUser &$user, string $permissionName)
    {
        $permission = $this->permissionMapper->fetchByName($permissionName);

        $this->revokePermissionById($user, $permission->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function addRole(EnhancedUser &$user, Role $role)
    {
        $this->addRoleById($user, $role->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function addRoleById(EnhancedUser &$user, string|int $roleId)
    {
        $userId = $user->getId();

        try {
            $pdos = $this->pdo->prepare('INSERT INTO public.user_role (user_id, role_id) VALUES (:user_id, :role_id)');

            $pdos->bindParam(':user_id', $userId, PDO::PARAM_INT);
            $pdos->bindParam(':role_id', $roleId, PDO::PARAM_INT);
            $pdos->execute();

            $user = $this->fetchById((int) $userId);
        } catch (PDOException $e) {
            //here log the error
        }
    }

    /**
     * {@inheritdoc}
     */
    public function addRoleByName(EnhancedUser &$user, string $roleName)
    {
        $userId = $user->getId();

        try {
            $pdos = $this->pdo->prepare('INSERT INTO public.user_role (user_id, role_id) VALUES (:user_id, (SELECT role_id FROM public.role WHERE name = :role_name))');

            $pdos->bindParam(':user_id', $userId, PDO::PARAM_INT);
            $pdos->bindParam(':role_name', $roleName, PDO::PARAM_STR);
            $pdos->execute();

            $user = $this->fetchById((int) $userId);
        } catch (PDOException $e) {
            //here log the error
        }
    }

    /**
     * {@inheritdoc}
     */
    public function removeRole(EnhancedUser &$user, Role $role)
    {
        $this->removeRoleById($user, $role->getId());
    }

    /**
     * {@inheritdoc}
     */
    public function removeRoleById(EnhancedUser &$user, string|int $roleId)
    {
        $userId = $user->getId();

        $pdos = $this->pdo->prepare('DELETE FROM public.user_role WHERE role_id = :role_id AND user_id = :user_id');

        $pdos->bindParam(':role_id', $roleId, PDO::PARAM_INT);
        $pdos->bindParam(':user_id', $userId, PDO::PARAM_INT);
        $pdos->execute();

        $user = $this->fetchById((int) $userId);
    }

    /**
     * {@inheritdoc}
     */
    public function removeRoleByName(EnhancedUser &$user, string $roleName)
    {
        $userId = $user->getId();

        $pdos = $this->pdo->prepare('DELETE FROM public.user_role WHERE role_id = (SELECT role_id FROM public.role WHERE name = :role_name) AND user_id = :user_id');

        $pdos->bindParam(':role_name', $roleName, PDO::PARAM_STR);
        $pdos->bindParam(':user_id', $userId, PDO::PARAM_INT);
        $pdos->execute();

        $user = $this->fetchById((int) $userId);
    }

    /**
     * {@inheritdoc}
     */
    protected function concreteCreate(): DomainObjectInterface
    {
        return new EnhancedUser($this->password, [], []);
    }

    /**
     * {@inheritdoc}
     */
    protected function checkDomainObjectType(DomainObjectInterface $domainObject): void
    {
        if (!($domainObject instanceof EnhancedUser)) {
            throw new InvalidArgumentException('Domain Object parameter must be instance of EnhancedUser class');
        }
    }
}
