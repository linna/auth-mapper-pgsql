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

use Linna\Authentication\Password;
use Linna\Storage\ExtendedPDO;
use PDO;

/**
 * Role To User Mapper.
 * Fetch only mapper utilized as helper for build Role and EnhancedUser mapper.
 */
class RoleToUserMapper implements RoleToUserMapperInterface
{
    /** @var Password Password utility for user object */
    protected Password $password;

    /** @var ExtendedPDO Database Connection */
    protected ExtendedPDO $pdo;

    /**
     * Class Constructor.
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
        $pdos = $this->pdo->prepare('
        SELECT u.user_id AS "id", u.uuid, u.name, u.email, u.description, u.password, u.active, u.created, u.last_update AS "lastUpdate"
        FROM public.user AS u
        INNER JOIN public.user_role AS ur 
        ON u.user_id = ur.user_id
        WHERE ur.role_id = :id');

        $pdos->bindParam(':id', $roleId, PDO::PARAM_INT);
        $pdos->execute();

        $array = $pdos->fetchAll(PDO::FETCH_CLASS, EnhancedUser::class, [$this->password, [], []]);

        return \array_combine(\array_column($array, 'id'), $array);
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

        $array = $pdos->fetchAll(PDO::FETCH_CLASS, EnhancedUser::class, [$this->password, [], []]);

        return \array_combine(\array_column($array, 'id'), $array);
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
    public function fetchByUserId(int|string $userId): array
    {
        $pdos = $this->pdo->prepare('
        SELECT r.role_id AS "id", r.name, r.description, r.active, r.created, r.last_update AS "lastUpdate"
        FROM public.role AS r
        INNER JOIN public.user_role AS ur ON r.role_id = ur.role_id
        WHERE ur.user_id = :id');

        $pdos->bindParam(':id', $userId, PDO::PARAM_INT);
        $pdos->execute();

        $array = $pdos->fetchAll(PDO::FETCH_CLASS, Role::class, [[], []]);

        return \array_combine(\array_column($array, 'id'), $array);
    }

    /**
     * {@inheritdoc}
     */
    public function fetchByUserName(string $userName): array
    {
        $pdos = $this->pdo->prepare('
        SELECT r.role_id AS "id", r.name, r.description, r.active, r.created, r.last_update AS "lastUpdate"
        FROM public.role AS r
        INNER JOIN public.user_role AS ur 
        ON r.role_id = ur.role_id
        INNER JOIN public.user AS u 
        ON ur.user_id = u.user_id
        WHERE u.name = :name');

        $pdos->bindParam(':name', $userName, PDO::PARAM_STR);
        $pdos->execute();

        $array = $pdos->fetchAll(PDO::FETCH_CLASS, Role::class, [[], []]);

        return \array_combine(\array_column($array, 'id'), $array);
    }
}
