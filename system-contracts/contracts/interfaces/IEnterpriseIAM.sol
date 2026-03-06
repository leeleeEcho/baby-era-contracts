// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IEnterpriseIAM {
    event OrganizationCreated(bytes32 indexed orgId, address indexed orgDID, address indexed owner);
    event OrganizationDeactivated(bytes32 indexed orgId);
    event RoleCreated(bytes32 indexed orgId, uint256 indexed roleId, bytes32 name, uint256 permissions);
    event RoleAssigned(bytes32 indexed orgId, address indexed member, uint256 indexed roleId);
    event RoleRevoked(bytes32 indexed orgId, address indexed member);

    function createOrganization(bytes32 orgId, address orgDID) external;
    function deactivateOrganization(bytes32 orgId) external;
    function getOrganization(bytes32 orgId) external view returns (address orgDID, address owner, uint256 memberCount, bool active);
    function createRole(bytes32 orgId, bytes32 name, uint256 permissions) external returns (uint256 roleId);
    function getRole(bytes32 orgId, uint256 roleId) external view returns (bytes32 name, uint256 permissions, address admin);
    function assignRole(bytes32 orgId, address member, uint256 roleId) external;
    function revokeRole(bytes32 orgId, address member) external;
    function getMemberRole(bytes32 orgId, address member) external view returns (uint256);
    function hasPermission(bytes32 orgId, address member, uint256 permission) external view returns (bool);
}
