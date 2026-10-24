mod control_plane_requests;

pub use control_plane_requests::{
    CreatePermissionRequest, CreateResourceTypeRequest, CreateRoleRequest,
    PermissionActionByNameInput, PermissionByNameInput, ResourceTypeActionByNameInput,
    ResourceTypeByNameInput, RoleActionByNameInput, RoleByNameInput, RolePermissionByNameInput,
    UpdateRoleRequest,
};

#[cfg(test)]
mod control_plane_requests_tests;
