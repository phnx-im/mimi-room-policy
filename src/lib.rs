// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::{
    collections::{HashMap, HashSet},
    iter,
};

type Timestamp = u32;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    // TYPE 1: Enforced by hub

    // Membership
    // Join,
    // Knock,
    // Invite,
    // Timeout { max_duration: u32 }, // Applies the role Disabled for the duration, then the user can remove the role by themselves
    Kick,                         // Removes all their roles
    GiveRole { role: RoleIndex }, // E.g. Admins can add moderators
    DropRole { role: RoleIndex }, // E.g. Admins can remove moderators

    GiveRoleSelf { role: RoleIndex }, // E.g. Alice assigns the role Artist to herself
    DropRoleSelf { role: RoleIndex },

    Disabled,

    // TYPE 2: Enforced by clients, the hubs helps if it can
    ReadMessage,
    SendMessage,
    EditMessage,

    IgnoreRatelimit,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Action {
    Kick,                                         // Removes all their roles
    GiveRole { target: String, role: RoleIndex }, // E.g. Admins can add moderators
    DropRole { target: String, role: RoleIndex }, // E.g. Admins can remove moderators

    // TYPE 2: Enforced by clients, the hubs helps if it can
    ReadMessage,
    SendMessage,
    EditMessage,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RoleIndex {
    Outsider = 0,  // For users not in the room
    Visitor = 1,   // Default for new members in public rooms
    Regular = 2,   // For approved members or new members in invite-only rooms
    Moderator = 3, // Extends regular
    Admin = 4,     // Extends moderator
    Owner = 5,     // Extends owner
    Custom(u16),
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Role {
    role_name: String,
    role_description: String,
    role_capabilities: Vec<Capability>, // TODO: This could also be a bitvector
    dependencies: Vec<RoleIndex>,       // What roles are required to have this role
    auto_expires: Option<Timestamp>,    // Timestamp after which this role is no longer active
    min: u32,
    max: Option<u32>,
    // min_active_participants_constraint: Option<u32>, // TODO: What does this mean?
    // max_active_participants_constraint: Option<u32>,
}

#[derive(Clone)]
pub struct PreAuthPerRoleList {
    target_role: RoleIndex, // TODO: RFC writes type Role, we use role index
    preauth_domain: String,
    preauth_workgroup: String, // Uri
    preauth_group: String,     // Uri
    preauth_user: String,      // Uri
}

#[derive(Clone)]
pub struct RoomPolicy {
    roles: HashMap<RoleIndex, Role>,
    pre_auth_list: Vec<PreAuthPerRoleList>,
    main_rate_limit: u32,
    thread_rate_limit: u32,
}

pub struct RoomState {
    policy: RoomPolicy,
    user_roles: HashMap<String, HashMap<RoleIndex, Timestamp>>,
}
impl RoomState {
    pub fn new(policy: &RoomPolicy, creator: &str) -> Self {
        let mut user_roles = HashMap::new();

        let mut owner_roles = HashSet::new();

        owner_roles.insert(RoleIndex::Regular);
        owner_roles.insert(RoleIndex::Moderator);
        owner_roles.insert(RoleIndex::Admin);
        owner_roles.insert(RoleIndex::Owner);

        Self {
            policy: policy.clone(),
            user_roles,
        }
    }

    pub fn user_capabilities(&self, user_id: &str) -> HashSet<Capability> {
        let mut roles = vec![RoleIndex::Outsider];

        if let Some(assigned_roles) = self.user_roles.get(user_id) {
            roles.extend(assigned_roles.iter())
        }

        let mut capabilities = HashSet::new();

        for role in roles {
            let role_info = self.policy.roles.get(&role).ok_or(()).unwrap();

            capabilities.extend(role_info.role_capabilities)
        }

        capabilities
    }

    pub fn user_has_role(&self, user_id: &str, role: RoleIndex) -> bool {
        let role_info = self.policy.roles.get(&role).ok_or(())?;
        self.user_roles
            .get(user_id)
            .and_then(|roles| roles.get(&role))
            .is_some_and(|role_time| {
                if let Some(expires_time) = role_info.auto_expires {
                    role_time < &expires_time
                } else {
                    true
                }
            })
    }

    pub fn give_user_role(&mut self, user_id: &str, role: RoleIndex) -> Result<(), ()> {
        let role_info = self.policy.roles.get(&role).ok_or(())?;
        for dependency in &role_info.dependencies {
            if !self.user_has_role(user_id, *dependency) {
                return Err(());
            }
        }

        if self
            .user_roles
            .entry(user_id.to_owned())
            .or_default()
            .insert(role)
        {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn make_actions(&mut self, user_id: &str, actions: &[Action]) -> Result<(), ()> {
        let user_capabilities = self.user_capabilities(user_id);

        for c in user_capabilities {
            if let Capability::Disabled = c {
                // TODO: Check duration
                return Err(());
            }
        }

        for action in actions {
            match action {
                Action::Kick { duration } => {
                    let mut capable = false;

                    for c in user_capabilities {
                        if let Capability::Kick { max_duration } = c {
                            if duration <= max_duration {
                                capable = true;
                                break;
                            }
                        }
                    }

                    if !capable {
                        return Err(());
                    }

                    todo!();
                }
                Capability::GiveRole { role } | Capability::GiveRoleSelf { role } => {
                    self.give_user_role(user_id, *role)
                }
                Capability::DropRole { role } => todo!(),
                Capability::DropRoleSelf { role } => todo!(),
                Capability::GiveAnyRole => todo!(),
                Capability::DropAnyRole => todo!(),
                Capability::ReadMessage => todo!(),
                Capability::SendMessage => todo!(),
                Capability::EditMessage => todo!(),
                Capability::IgnoreRatelimit | Capability::Disabled { .. } => return Err(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles() {
        let mut roles = HashMap::new();

        roles.insert(
            RoleIndex::Outsider,
            Role {
                role_name: "Outsider".to_owned(),
                role_description: "Not in the room".to_owned(),
                role_capabilities: vec![],
                dependencies: vec![],
                min: 0,
                max: Some(0), // There should be no outsiders inside the room
            },
        );

        roles.insert(
            RoleIndex::Visitor,
            Role {
                role_name: "Visitor".to_owned(),
                role_description: "Can read, but not send messages".to_owned(),
                role_capabilities: vec![Capability::ReadMessage],
                dependencies: vec![],
                min: 0,
                max: None,
            },
        );

        roles.insert(
            RoleIndex::Regular,
            Role {
                role_name: "Regular user".to_owned(),
                role_description: "Can read and send messages".to_owned(),
                role_capabilities: vec![Capability::ReadMessage, Capability::SendMessage],
                dependencies: vec![],
                min: 1,
                max: None,
            },
        );

        roles.insert(
            RoleIndex::Moderator,
            Role {
                role_name: "Moderator".to_owned(),
                role_description: "Can edit or remove messages sent by others".to_owned(),
                role_capabilities: vec![Capability::EditMessage],
                dependencies: vec![RoleIndex::Regular],
                min: 1,
                max: None,
            },
        );

        roles.insert(
            RoleIndex::Admin,
            Role {
                role_name: "Admin".to_owned(),
                role_description: "Can do anything".to_owned(),
                role_capabilities: vec![
                    Capability::EditMessage,
                    Capability::GiveAnyRole,
                    Capability::DropAnyRole,
                ],
                dependencies: vec![RoleIndex::Regular],
                min: 1,
                max: None,
            },
        );

        roles.insert(
            RoleIndex::Owner,
            Role {
                role_name: "Owner".to_owned(),
                role_description: "Cannot be influenced by admins".to_owned(),
                role_capabilities: vec![
                    Capability::EditMessage,
                    Capability::GiveAnyRole,
                    Capability::DropAnyRole,
                ],
                dependencies: vec![RoleIndex::Admin],
                min: 1,
                max: None,
            },
        );

        let policy = RoomPolicy {
            roles,
            main_rate_limit: 10,  // wait 10 seconds after every message
            thread_rate_limit: 0, // no need to wait in threads
            pre_auth_list: vec![],
        };

        let mut room_state = RoomState::new(&policy, "@timo:phnx.im");

        room_state
            .use_capability("@spam:phnx.im", &Capability::Join)
            .unwrap();
    }
}
