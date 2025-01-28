// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Mimi Room Policy
//!
//! This proposal is for role-based access control mode with a set of predefined rules and the option to extend it with custom roles.
//!
//!
//! ## Basics
//!
//! The most important roles are predefined and have special behavior to make it easy for clients to understand them. These roles have a hierarchy that corresponds to the level of trust in users.
//! 1. **Outsiders** are not in the room and not trusted at all.
//! 2. **Visitors** are members of the room with the lowest amount of trust and have restricted capabilities.
//! 3. **Regular users** have a standard level of trust and can interact normally with the room.
//! 4. **Moderators** are trusted to manage the discussion in the room.
//! 5. **Admins** have a very high level of trust and can change almost any aspect of the room.
//! 6. The **Owner** is the single member with more power than admins.
//!
//! A custom role can be used for sets of users that do not fit in the above hierarchy. For example, consider a room dedicated to game development:
//! - A custom role **Programmer** allows programmers to send messages into the "#programming" thread.
//! - A custom role **Bot** is added to all bot users to indicate that their responses are automated.
//! - Users can give a custom role **He/Him**, **She/Her** or **They/Them** to themselves to specify their preference.
//!
//! For the default room variants, see [`PolicyTemplate`].
//!

use std::{
    collections::{hash_map, HashMap, HashSet},
    ops::Deref,
};

/// An error returned from room policy operations.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// The operation would have no effect.
    NothingToDo,

    /// The target role is not part of the room policy.
    RoleNotDefined,

    /// The user is not in the room.
    UserNotInRoom,

    /// A user would have a role, but not the dependency roles.
    RoleDependencyViolated,

    /// Too few or too many users would have a role.
    RoleMinMaxViolated,

    /// The user does not have the required capability or the target is protected from the user.
    NotCapable,

    /// Could not create a new role, because a role with this RoleIndex already exists.
    RoleAlreadyExists,

    /// The action could not be taken, because of special rules for the relevant capability.
    SpecialCapability,

    /// The action could not be taken, because of special rules for the relevant role.
    SpecialRole,

    /// A string value could not be set, because it is too long.
    StringTooLong,

    /// The dependencies could not be changed.
    InvalidRoleDependencies,

    /// A role could not be removed, because there are still users with this role.
    RoleInUse,

    /// The user was banned.
    Banned,
}

type Result<T> = std::result::Result<T, Error>;

/// The specified roles have a special features in the room policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum RoleIndex {
    /// Outsiders are not in the room and are not trusted at all.
    Outsider = 0,

    /// Restricted users are members of the room with the lowest amount of trust and have limited capabilities.
    Restricted = 1,

    /// Regular users have a standard level of trust and can interact normally with the room.
    Regular = 2,

    /// Moderators are trusted to manage the discussion in the room.
    Moderator = 3,

    /// Admins have a very high level of trust and can change almost any aspect of the room.
    Admin = 4,

    /// The Owner is the single member with more power than admins.
    Owner = 5,

    /// Custom roles
    Custom(u16),
}

impl RoleIndex {
    // Returns true if the role is RoleIndex::Custom(_).
    pub fn is_custom(&self) -> bool {
        matches!(self, RoleIndex::Custom(_))
    }
}

/// Capabilities grant permission to do certain actions and are always positive.
///
/// The following set of actions are not capabilities, because they can be used any member:
/// - ReadMessage: Read messages sent by any user in the room
/// - DropRoleSelf: The user removes a role from themselves, taking away some capabilities.
/// - Leave: Leave the room
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    // TYPE 1: Enforced by hub
    /// Ask to be invited into the room.
    Knock,

    /// Force a user to leave the room. They are allowed to rejoin.
    /// This effectively removes all roles from the user.
    Kick,

    /// Force a user to leave the room. They cannot rejoin.
    Ban,

    /// Adding a role to a user, granting them some capabilities.
    /// E.g. Admins can add moderators.
    GiveRoleOther { role: RoleIndex },

    /// Removing a role from a user, taking away some capabilities.
    /// E.g. Admins can remove moderators.
    DropRoleOther { role: RoleIndex },

    /// A user adds a role to themselves, granting them some capabilities.
    /// E.g. Alice assigns the "Artist" role to herself.
    GiveRoleSelf { role: RoleIndex },

    /// A user does not have to respect the ratelimit defined in the room policy.
    IgnoreRatelimit,

    // TYPE 2: Enforced by clients, the hubs helps if it can
    /// Send a message of a specific type into the room.
    SendMessage { message_type: MessageType },

    /// Edit messages sent by others.
    /// E.g. Removing sensitive details from a message.
    EditMessageOther,

    /// Edit message sent by yourself.
    /// E.g. Clarifying a question or correcting typos.
    EditMessageSelf,

    /// Delete messages sent by others.
    /// E.g. Removing spam.
    DeleteMessageOther,

    /// Deleting messages sent by yourself.
    /// E.g. After accidentally sending a message into a wrong chat.
    DeleteMessageSelf,
}

/// Different types of messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MessageType {
    /// A reaction message.
    Reaction,

    /// A text message.
    Text,

    /// An image.
    Image,

    /// A regular audio message
    Audio,

    /// A voice audio message.
    Voice,

    /// A video.
    Video,

    /// An arbitrary file.
    File,

    /// Message that start or end a conference
    ControlConference,
}

/// An action that makes use of capabilities.
///
/// There is a lot of similarity to `Capability`, but this is a separate enum because some actions require more information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Action {
    /// Ask to be invited into the room.
    Knock,

    /// Drops all their roles. You can kick yourself to leave the room.
    Kick {
        target: String,
    },

    /// Drops all their roles and does not allow them to rejoin. You cannot ban yourself.
    Ban {
        target: String,
        reason: String,
        until: Option<u32>,
    },

    /// Add a role to a user.
    // E.g. Admins can add the moderator role to regular users.
    GiveRole {
        target: String,
        role: RoleIndex,
    },

    /// Remove a role from a user.
    DropRole {
        target: String,
        role: RoleIndex,
    },

    // TYPE 2: Enforced by clients, the hubs helps if it can
    /// Send messages in the room.
    SendMessage {
        message_type: MessageType,
    },

    /// Edit messages from yourself or others.
    EditMessage {
        target: String,
    },

    /// Delete messages from yourself or others.
    DeleteMessage {
        target: String,
    },

    // Add, change or remove roles. There is no corresponding capability, only admins can do this.
    ChangePolicyRole {
        target: RoleIndex,
        action: RoleChange,
    },

    ChangePolicyProperty {
        todo: (),
    },
}

/// A policy change to a role.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RoleChange {
    /// Create a new custom role.
    New(RoleInfo),

    /// Remove a custom role.
    Remove,

    /// Change the name of a custom role.
    ChangeName(String),

    /// Change the description of a custom role.
    ChangeDescription(String),

    /// Add a capability to a role.
    AddCapability(Capability),

    /// Remove a capability from a role.
    RemoveCapability(Capability),

    /// Add a dependency to a role.
    AddDependency(RoleIndex),

    /// Remove a dependency from a role.
    RemoveDependency(RoleIndex),

    /// Set minimum number of members with this role.
    SetMin(u32),

    // Set maximum number of members with this role.
    SetMax(Option<u32>),
}

/// The definition of a role for the room policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RoleInfo {
    role_name: String,
    role_description: String,
    role_capabilities: Vec<Capability>, // TODO: This could also be a bitvector
    dependencies: Vec<RoleIndex>,       // What roles are required to have this role
    min: u32,
    max: Option<u32>,
    // min_active_participants_constraint: Option<u32>, // TODO: What does this mean?
    // max_active_participants_constraint: Option<u32>,
}

// #[derive(Clone)]
// pub struct PreAuthPerRoleList {
//     target_role: RoleIndex, // TODO: RFC writes type Role, we use role index
//     preauth_domain: String,
//     preauth_workgroup: String, // Uri
//     preauth_group: String,     // Uri
//     preauth_user: String,      // Uri
// }

/// The set of rules that the room will follow.
#[derive(Clone)]
pub struct RoomPolicy {
    roles: HashMap<RoleIndex, RoleInfo>,
    parent_room: Option<String>,
    password_protected: Option<String>,
    delivery_notifications: Optionality,
    read_receipts: Optionality,
    pseudonymous_ids: bool,
    // pre_auth_list: Vec<PreAuthPerRoleList>,
    // main_rate_limit_ms: u32,
    // thread_rate_limit_ms: u32,
}

/// A value to indicate preference of a feature.
#[derive(Clone)]
pub enum Optionality {
    /// The decision is up to the user or client.
    Optional = 0,

    /// The feature must be active.
    Required = 1,

    /// The feature must be disabled.
    Forbidden = 2,
}

/// The state of the room.
#[derive(Clone)]
pub struct RoomState {
    /// The general rules for the room.
    policy: RoomPolicy,

    /// The current roles for each user.
    /// Users in this map are all part of the room and allowed to read messages.
    /// A user with no roles is automatically removed from.
    user_roles: HashMap<String, HashSet<RoleIndex>>,

    users_banned: HashMap<String, BanInfo>,
}

#[derive(Clone)]
struct BanInfo {
    creator: String,
    reason: String,
    until: Option<u32>,
}

/// A list of presets for common room policies.
pub enum PolicyTemplate {
    /// A public room where visitors cannot chat.
    ///
    /// - **Outsiders** can join as Restricted users
    /// - **Restricted users** can invite more users, but can only send reactions
    /// - **Regular users** can chat normally
    Announcement,

    /// A public room where all members can chat.
    ///
    /// - **Outsiders** can join as Regular users
    /// - **Regular users** can chat normally
    Public,

    /// A private room where members can send invites.
    ///
    /// - **Outsiders** cannot join
    /// - **Regular users** can chat and invite users as Regular users
    InviteOnly,

    /// A private room where anyone can knock.
    ///
    /// - **Outsiders** can knock
    /// - **Regular users** can chat and invite users as Regular users
    Knock,

    /// A private room where only admins can invite.
    ///
    /// - **Outsiders** cannot join
    /// - **Regular users** can chat, but cannot invite more users
    FixedMembership,

    /// A room where user can join if they are part of the parent room.
    ///
    /// TODO
    ParentDependent,
}

/// The state of the room. The consistency checks verifed that the state is valid.
pub struct VerifiedRoomState(RoomState);

impl RoomState {
    /// Construct a new room using the specified template.
    pub fn new_from_template(owner: &str, template: PolicyTemplate) -> Self {
        let mut roles = HashMap::new();

        roles.insert(
            RoleIndex::Outsider,
            RoleInfo {
                role_name: "Outsider".to_owned(),
                role_description: "Not in the room".to_owned(),
                role_capabilities: match template {
                    PolicyTemplate::Announcement | PolicyTemplate::Public => {
                        vec![Capability::GiveRoleSelf {
                            role: RoleIndex::Restricted,
                        }]
                    }
                    PolicyTemplate::Knock => vec![Capability::Knock],
                    _ => vec![],
                },
                dependencies: vec![],
                min: 0,
                max: Some(0), // There should be no outsiders inside the room
            },
        );

        roles.insert(
            RoleIndex::Restricted,
            match template {
                PolicyTemplate::Announcement => RoleInfo {
                    role_name: "Visitor".to_owned(),
                    role_description: "Can only send reactions".to_owned(),
                    role_capabilities: vec![
                        Capability::EditMessageSelf,
                        Capability::DeleteMessageSelf,
                        Capability::SendMessage {
                            message_type: MessageType::Reaction,
                        },
                        Capability::GiveRoleOther {
                            role: RoleIndex::Restricted, // Invite users
                        },
                    ],
                    dependencies: vec![],
                    min: 0,
                    max: None,
                },

                PolicyTemplate::Public
                | PolicyTemplate::InviteOnly
                | PolicyTemplate::Knock
                | PolicyTemplate::FixedMembership => RoleInfo {
                    role_name: "Restricted".to_owned(),
                    role_description: "Can only read".to_owned(),
                    role_capabilities: vec![
                        Capability::EditMessageSelf,
                        Capability::DeleteMessageSelf,
                    ],
                    dependencies: vec![],
                    min: 0,
                    max: None,
                },

                PolicyTemplate::ParentDependent => todo!(),
            },
        );

        roles.insert(
            RoleIndex::Regular,
            RoleInfo {
                role_name: "Regular user".to_owned(),
                role_description: "Can read and send messages normally".to_owned(),
                role_capabilities: vec![
                    // Send messages
                    Capability::SendMessage {
                        message_type: MessageType::Text,
                    },
                    Capability::SendMessage {
                        message_type: MessageType::Image,
                    },
                    Capability::SendMessage {
                        message_type: MessageType::Voice,
                    },
                    Capability::SendMessage {
                        message_type: MessageType::Audio,
                    },
                    Capability::SendMessage {
                        message_type: MessageType::Video,
                    },
                    Capability::SendMessage {
                        message_type: MessageType::File,
                    },
                    // No conference control messages are allowed

                    // No rate limit for approved users
                    Capability::IgnoreRatelimit,
                ],
                dependencies: vec![RoleIndex::Restricted],
                min: 0,
                max: None,
            },
        );

        roles.insert(
            RoleIndex::Moderator,
            RoleInfo {
                role_name: "Moderator".to_owned(),
                role_description:
                    "Can edit or remove messages sent by others. Can promote more moderators"
                        .to_owned(),
                role_capabilities: vec![
                    // Moderate
                    Capability::EditMessageOther,
                    Capability::DeleteMessageOther,
                    Capability::Kick,
                    Capability::Ban,
                    // Control a conference
                    Capability::SendMessage {
                        message_type: MessageType::ControlConference,
                    },
                    // Approve members
                    Capability::GiveRoleOther {
                        role: RoleIndex::Regular,
                    },
                    // Add more moderators
                    Capability::GiveRoleOther {
                        role: RoleIndex::Moderator,
                    },
                ],
                dependencies: vec![RoleIndex::Regular],
                min: 0,
                max: None,
            },
        );

        roles.insert(
            RoleIndex::Admin,
            RoleInfo {
                role_name: "Admin".to_owned(),
                role_description: "Has all capabilities".to_owned(),
                role_capabilities: vec![
                    // Admins have all capabilities anyway
                ],
                dependencies: vec![RoleIndex::Moderator],
                min: 0,
                max: None,
            },
        );

        roles.insert(
            RoleIndex::Owner,
            RoleInfo {
                role_name: "Owner".to_owned(),
                role_description: "Is protected from admins".to_owned(),
                role_capabilities: vec![
                    // Admins have all capabilities anyway
                ],
                dependencies: vec![RoleIndex::Admin],
                min: 1,
                max: Some(1),
            },
        );

        let policy = RoomPolicy {
            roles,
            parent_room: None,
            password_protected: None,
            delivery_notifications: Optionality::Optional,
            read_receipts: Optionality::Optional,
            pseudonymous_ids: false,
            //pre_auth_list: vec![],
            //main_rate_limit_ms: 10000, // wait 10 seconds after every message
            //thread_rate_limit_ms: 100, // almost no delay in threads
        };

        RoomState::new(owner, &policy)
    }

    /// Construct a new room with the given policy.
    pub fn new(owner: &str, policy: &RoomPolicy) -> Self {
        let mut user_roles = HashMap::new();

        let mut owner_roles = HashSet::new();

        owner_roles.insert(RoleIndex::Restricted);
        owner_roles.insert(RoleIndex::Regular);
        owner_roles.insert(RoleIndex::Moderator);
        owner_roles.insert(RoleIndex::Admin);
        owner_roles.insert(RoleIndex::Owner);

        user_roles.insert(owner.to_owned(), owner_roles);

        Self {
            policy: policy.clone(),
            users_banned: HashMap::new(),
            user_roles,
        }
    }

    /// Returns true if the user has the Moderator role.
    pub fn is_mod(&self, user_id: &str) -> Result<bool> {
        Ok(self
            .user_roles
            .get(user_id)
            .ok_or(Error::UserNotInRoom)?
            .contains(&RoleIndex::Moderator))
    }

    /// Returns true if the user has the Admin role.
    pub fn is_admin(&self, user_id: &str) -> Result<bool> {
        Ok(self
            .user_roles
            .get(user_id)
            .is_some_and(|list| list.contains(&RoleIndex::Admin)))
    }

    /// Returns true if the user has the Owner role.
    pub fn is_owner(&self, user_id: &str) -> Result<bool> {
        Ok(self
            .user_roles
            .get(user_id)
            .ok_or(Error::UserNotInRoom)?
            .contains(&RoleIndex::Owner))
    }

    /// Returns true if the target is protected from the actor:
    /// - Owners are protected.
    /// - Admins are protected, except from the owner.
    /// - Moderators are protected, except from admins.
    /// - Users are not protected from themselves.
    ///
    /// Because all admins are also moderators, admins are protected from moderators.
    pub fn is_protected_from(&self, actor: &str, target: &str) -> Result<bool> {
        if actor == target {
            return Ok(false);
        }

        Ok(self.is_owner(target)?
            || self.is_admin(target)? && !self.is_owner(actor)?
            || self.is_mod(target)? && self.is_admin(actor)?)
    }

    /// The list of all capabilities of a user as determined by their roles.
    ///
    /// - Admins implicitly have all capabilities, even those not listed by this function.
    /// - If a user has no roles, they receive the capabilities of the Outsider role.
    pub fn user_explicit_capabilities(&self, user_id: &str) -> Result<HashSet<Capability>> {
        let mut roles = HashSet::new();

        if let Some(assigned_roles) = self.user_roles.get(user_id) {
            roles.extend(assigned_roles);
        } else {
            roles.insert(RoleIndex::Outsider);
        }

        let mut capabilities = HashSet::new();

        for role in roles {
            let role_info = self.policy.roles.get(&role).ok_or(Error::RoleNotDefined)?;

            capabilities.extend(role_info.role_capabilities.iter())
        }

        Ok(capabilities)
    }

    /// Returns true if the user has this capability explicitly or if they are an administrator.
    pub fn is_capable(&self, user_id: &str, capability: Capability) -> Result<bool> {
        Ok(self
            .user_explicit_capabilities(user_id)?
            .contains(&capability)
            || self.is_admin(user_id)?)
    }

    /// Returns the sorted list of all users.
    pub fn joined_users(&self) -> Vec<String> {
        let mut list = self.user_roles.keys().cloned().collect::<Vec<_>>();

        list.sort();

        list
    }

    /// Adds a role to a user.
    fn give_user_role(&mut self, user_id: &str, role: RoleIndex) -> Result<()> {
        if self
            .user_roles
            .entry(user_id.to_owned())
            .or_default()
            .insert(role)
        {
            Ok(())
        } else {
            Err(Error::NothingToDo)
        }
    }

    /// Removes a role from a user.
    fn drop_user_role(&mut self, user_id: &str, role: RoleIndex) -> Result<()> {
        if self
            .user_roles
            .get_mut(user_id)
            .ok_or(Error::UserNotInRoom)?
            .remove(&role)
        {
            Ok(())
        } else {
            Err(Error::NothingToDo)
        }
    }

    fn consistency_checks(mut self) -> Result<VerifiedRoomState> {
        // These roles are always defined
        assert!(self.policy.roles.contains_key(&RoleIndex::Outsider));
        assert!(self.policy.roles.contains_key(&RoleIndex::Restricted));
        assert!(self.policy.roles.contains_key(&RoleIndex::Regular));
        assert!(self.policy.roles.contains_key(&RoleIndex::Moderator));
        assert!(self.policy.roles.contains_key(&RoleIndex::Admin));
        assert!(self.policy.roles.contains_key(&RoleIndex::Owner));

        let mut role_counts = HashMap::new();
        // Role dependencies
        for roles_of_user in self.user_roles.values() {
            for role in roles_of_user {
                *role_counts.entry(role).or_insert(0_u32) += 1;
                let role_info = self.policy.roles.get(role).ok_or(Error::RoleNotDefined)?;
                for dependency in &role_info.dependencies {
                    let _dependency_info =
                        self.policy.roles.get(role).ok_or(Error::RoleNotDefined)?;
                    if !roles_of_user.contains(dependency) {
                        return Err(Error::RoleDependencyViolated);
                    }
                }
            }
        }

        for (role, role_info) in &mut self.policy.roles {
            role_info.role_capabilities.sort();
            role_info.role_capabilities.dedup();

            role_info.dependencies.sort();
            role_info.dependencies.dedup();

            // Some capabilities are only allowed in specific circumstances
            for capability in &role_info.role_capabilities {
                // Outsiders can only knock or join
                if (*capability != Capability::Knock
                    && !matches!(capability, Capability::GiveRoleSelf { .. }))
                    && *role == RoleIndex::Outsider
                {
                    return Err(Error::SpecialRole);
                }

                // Admins and Owner can already do everything, they don't need explicit capabilities
                if *role == RoleIndex::Admin || *role == RoleIndex::Owner {
                    return Err(Error::SpecialRole);
                }
            }

            // Only custom roles can have arbitrary dependencies
            let dependencies_valid = match role {
                RoleIndex::Outsider => role_info.dependencies == vec![],
                RoleIndex::Restricted => role_info.dependencies == vec![],
                RoleIndex::Regular => role_info.dependencies == vec![RoleIndex::Restricted],
                RoleIndex::Moderator => role_info.dependencies == vec![RoleIndex::Regular],
                RoleIndex::Admin => role_info.dependencies == vec![RoleIndex::Moderator],
                RoleIndex::Owner => role_info.dependencies == vec![RoleIndex::Admin],
                RoleIndex::Custom(_) => {
                    // No member has role Outsider and all members have role Restricted
                    !role_info.dependencies.contains(&RoleIndex::Outsider)
                        && !role_info.dependencies.contains(&RoleIndex::Restricted)
                }
            };

            if !dependencies_valid {
                return Err(Error::InvalidRoleDependencies);
            }

            if !role.is_custom()
                && (!role_info.role_name.is_empty() || !role_info.role_description.is_empty())
            {
                // Special roles always have empty names, because clients should display their own translated names.
                //
                // TODO: Or maybe not?
                // return Err(Error::SpecialRole);
            }

            if role_info.role_name.len() > 1000 {
                return Err(Error::StringTooLong);
            }

            if role_info.role_description.len() > 1000 {
                return Err(Error::StringTooLong);
            }

            if role_info.dependencies.contains(&role) {
                return Err(Error::InvalidRoleDependencies);
                // TODO: Detect transitive dependency loops
            }

            // Min and max
            let count = *role_counts.get(&role).unwrap_or(&0);
            if count < role_info.min || role_info.max.is_some_and(|max| count > max) {
                return Err(Error::RoleMinMaxViolated);
            }
        }

        // Drop users that have no role
        self.user_roles.retain(|_user_id, roles| !roles.is_empty());

        // Banned users are not in the room
        for (user, ban) in &self.users_banned {
            let banned = match ban.until {
                None => true,
                Some(_) => todo!(),
            };

            if banned && self.user_roles.contains_key(user) {
                return Err(Error::Banned);
            }
        }

        Ok(VerifiedRoomState(self))
    }

    pub fn join_room_actions(&self, user_id: &str) -> Result<Vec<Action>> {
        let mut actions = Vec::new();

        for capability in &self
            .policy
            .roles
            .get(&RoleIndex::Outsider)
            .ok_or(Error::RoleNotDefined)?
            .role_capabilities
        {
            if let Capability::GiveRoleSelf { role } = capability {
                actions.push(Action::GiveRole {
                    target: user_id.to_owned(),
                    role: *role,
                });
            }
        }

        if actions.is_empty() {
            return Err(Error::NotCapable);
        }

        Ok(actions)
    }

    /// Applies the list of actions in the given order. This will not verify consistency.
    pub fn try_make_actions(mut self, user_id: &str, actions: &[Action]) -> Result<Self> {
        assert!(!actions.is_empty());

        if let Some(ban) = self.users_banned.get(user_id) {
            match ban.until {
                None => return Err(Error::Banned),
                Some(_) => todo!(),
            }
        }

        for action in actions {
            match action {
                Action::Knock => todo!(),
                Action::Kick { target } => {
                    if user_id != target && !self.is_capable(user_id, Capability::Kick)? {
                        return Err(Error::NotCapable);
                    }

                    if self.is_protected_from(user_id, target)? {
                        return Err(Error::NotCapable);
                    }

                    for role in self
                        .user_roles
                        .get(target)
                        .ok_or(Error::UserNotInRoom)?
                        .clone()
                    {
                        self.drop_user_role(target, role)?;
                    }
                }
                Action::Ban {
                    target,
                    reason,
                    until,
                } => {
                    if user_id == target || !self.is_capable(user_id, Capability::Ban)? {
                        return Err(Error::NotCapable);
                    }

                    if self.is_protected_from(user_id, target)? {
                        return Err(Error::NotCapable);
                    }

                    // Kick
                    for role in self
                        .user_roles
                        .get(target)
                        .ok_or(Error::UserNotInRoom)?
                        .clone()
                    {
                        self.drop_user_role(target, role)?;
                    }

                    // Ban
                    // If a ban already existed, this will replace it.
                    self.users_banned.insert(
                        target.clone(),
                        BanInfo {
                            creator: user_id.to_owned(),
                            reason: reason.clone(),
                            until: *until,
                        },
                    );
                }
                Action::GiveRole { target, role } => {
                    let valid_to_self = target == user_id
                        && self.is_capable(user_id, Capability::GiveRoleSelf { role: *role })?;

                    let valid_to_other =
                        self.is_capable(user_id, Capability::GiveRoleOther { role: *role })?;

                    if !valid_to_self && !valid_to_other {
                        return Err(Error::NotCapable);
                    }

                    self.give_user_role(target, *role)?;
                }
                Action::DropRole { target, role } => {
                    let valid_to_self = target == user_id;

                    let valid_to_other = self
                        .is_capable(user_id, Capability::DropRoleOther { role: *role })?
                        && !self.is_protected_from(user_id, target)?;

                    if !valid_to_self && !valid_to_other {
                        return Err(Error::NotCapable);
                    }

                    self.drop_user_role(target, *role)?;
                }
                Action::SendMessage { message_type } => {
                    if !self.is_capable(
                        user_id,
                        Capability::SendMessage {
                            message_type: *message_type,
                        },
                    )? {
                        return Err(Error::NotCapable);
                    }

                    // TODO: Check
                    // - rate limit
                    // - max message size
                    // - allowed content types
                }
                Action::EditMessage { target } => {
                    let valid_to_self = target == user_id
                        && self.is_capable(user_id, Capability::EditMessageSelf)?;

                    let valid_to_other = self.is_capable(user_id, Capability::EditMessageOther)?
                        && !self.is_protected_from(user_id, target)?;

                    if !valid_to_self && !valid_to_other {
                        return Err(Error::NotCapable);
                    }

                    // TODO: Check
                    // - max message size
                    // - allowed content types
                }

                Action::DeleteMessage { target } => {
                    let valid_to_self = target == user_id
                        && self.is_capable(user_id, Capability::DeleteMessageSelf)?;

                    let valid_to_other = self
                        .is_capable(user_id, Capability::DeleteMessageOther)?
                        && !self.is_protected_from(user_id, target)?;

                    if !valid_to_self && !valid_to_other {
                        return Err(Error::NotCapable);
                    }
                }
                Action::ChangePolicyRole { target, action } => {
                    if !self.is_admin(user_id)? {
                        return Err(Error::NotCapable);
                    }

                    match action {
                        RoleChange::New(role_info) => {
                            if !target.is_custom() || self.policy.roles.contains_key(target) {
                                return Err(Error::RoleAlreadyExists);
                            }

                            self.policy.roles.insert(*target, role_info.clone());
                        }
                        RoleChange::Remove => {
                            for (_user, roles) in &self.user_roles {
                                if roles.contains(target) {
                                    return Err(Error::RoleInUse);
                                }
                            }

                            self.policy.roles.remove(target);
                        }
                        RoleChange::ChangeName(new_name) => {
                            let Some(role_info) = self.policy.roles.get_mut(target) else {
                                return Err(Error::RoleNotDefined);
                            };

                            if role_info.role_name == *new_name {
                                return Err(Error::NothingToDo);
                            }

                            role_info.role_name = new_name.clone();
                        }
                        RoleChange::ChangeDescription(new_description) => {
                            let Some(role_info) = self.policy.roles.get_mut(target) else {
                                return Err(Error::RoleNotDefined);
                            };

                            if role_info.role_description == *new_description {
                                return Err(Error::NothingToDo);
                            }

                            role_info.role_description = new_description.clone();
                        }
                        RoleChange::AddCapability(capability) => {
                            let Some(role_info) = self.policy.roles.get_mut(target) else {
                                return Err(Error::RoleNotDefined);
                            };

                            if role_info.role_capabilities.contains(capability) {
                                return Err(Error::NothingToDo);
                            }

                            role_info.role_capabilities.push(capability.clone());
                        }
                        RoleChange::RemoveCapability(capability) => {
                            let Some(role_info) = self.policy.roles.get_mut(target) else {
                                return Err(Error::RoleNotDefined);
                            };

                            if !role_info.role_capabilities.contains(capability) {
                                return Err(Error::NothingToDo);
                            }

                            role_info.role_capabilities.retain(|x| x != capability);
                        }
                        RoleChange::AddDependency(dependency) => {
                            let Some(role_info) = self.policy.roles.get_mut(target) else {
                                return Err(Error::RoleNotDefined);
                            };

                            if role_info.dependencies.contains(dependency) {
                                return Err(Error::NothingToDo);
                            }

                            role_info.dependencies.push(*dependency);
                        }
                        RoleChange::RemoveDependency(dependency) => {
                            let Some(role_info) = self.policy.roles.get_mut(target) else {
                                return Err(Error::RoleNotDefined);
                            };

                            if !role_info.dependencies.contains(dependency) {
                                return Err(Error::NothingToDo);
                            }

                            role_info.dependencies.retain(|x| x != dependency);
                        }
                        RoleChange::SetMin(new_min) => {
                            let Some(role_info) = self.policy.roles.get_mut(target) else {
                                return Err(Error::RoleNotDefined);
                            };

                            if role_info.min == *new_min {
                                return Err(Error::NothingToDo);
                            }

                            role_info.min = *new_min;
                        }
                        RoleChange::SetMax(new_max) => {
                            let Some(role_info) = self.policy.roles.get_mut(target) else {
                                return Err(Error::RoleNotDefined);
                            };

                            if role_info.max == *new_max {
                                return Err(Error::NothingToDo);
                            }

                            role_info.max = *new_max;
                        }
                    }
                }
                Action::ChangePolicyProperty { todo } => todo!(),
            }
        }

        Ok(self)
    }
}

impl VerifiedRoomState {
    pub fn new_from_template(owner: &str, template: PolicyTemplate) -> Self {
        let state = RoomState::new_from_template(owner, template);

        state
            .consistency_checks()
            .expect("new_from_template is always valid")
    }

    pub fn new(owner: &str, policy: &RoomPolicy) -> Result<Self> {
        let state = RoomState::new(owner, policy);

        state.consistency_checks()
    }

    pub fn make_actions(&mut self, user_id: &str, actions: &[Action]) -> Result<()> {
        let result = self.0.clone().try_make_actions(user_id, actions)?;

        *self = result.consistency_checks()?;

        Ok(())
    }
}

impl Deref for VerifiedRoomState {
    type Target = RoomState;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_room() -> VerifiedRoomState {
        let mut room_state =
            VerifiedRoomState::new_from_template("@owner:phnx.im", PolicyTemplate::Public);

        // Users join
        room_state
            .make_actions(
                "@visitor:phnx.im",
                &room_state.join_room_actions("@visitor:phnx.im").unwrap(),
            )
            .unwrap();
        room_state
            .make_actions(
                "@regular:phnx.im",
                &room_state.join_room_actions("@regular:phnx.im").unwrap(),
            )
            .unwrap();
        room_state
            .make_actions(
                "@mod:phnx.im",
                &room_state.join_room_actions("@mod:phnx.im").unwrap(),
            )
            .unwrap();
        room_state
            .make_actions(
                "@admin:phnx.im",
                &room_state.join_room_actions("@admin:phnx.im").unwrap(),
            )
            .unwrap();

        // Promote all users
        room_state
            .make_actions(
                "@owner:phnx.im",
                &[
                    // Regular
                    Action::GiveRole {
                        target: "@regular:phnx.im".to_owned(),
                        role: RoleIndex::Regular,
                    },
                    Action::GiveRole {
                        target: "@mod:phnx.im".to_owned(),
                        role: RoleIndex::Regular,
                    },
                    Action::GiveRole {
                        target: "@admin:phnx.im".to_owned(),
                        role: RoleIndex::Regular,
                    },
                    // Moderator
                    Action::GiveRole {
                        target: "@mod:phnx.im".to_owned(),
                        role: RoleIndex::Moderator,
                    },
                    Action::GiveRole {
                        target: "@admin:phnx.im".to_owned(),
                        role: RoleIndex::Moderator,
                    },
                    // Admin
                    Action::GiveRole {
                        target: "@admin:phnx.im".to_owned(),
                        role: RoleIndex::Admin,
                    },
                ],
            )
            .unwrap();

        room_state
    }

    #[test]
    fn invite_only_room() {
        let room_state =
            VerifiedRoomState::new_from_template("@owner:phnx.im", PolicyTemplate::InviteOnly);

        // Only the owner is in the room
        assert_eq!(room_state.joined_users(), vec!["@owner:phnx.im".to_owned()]);

        // @bob cannot join
        assert_eq!(
            room_state.join_room_actions("@bob:phnx.im"),
            Err(Error::NotCapable)
        );
    }

    #[test]
    fn setup_public_room() {
        let mut room_state =
            VerifiedRoomState::new_from_template("@owner:phnx.im", PolicyTemplate::Announcement);

        // Only the owner is in the room
        assert_eq!(room_state.joined_users(), vec!["@owner:phnx.im".to_owned()]);

        // @bob joins
        room_state
            .make_actions(
                "@bob:phnx.im",
                &room_state.join_room_actions("@bob:phnx.im").unwrap(),
            )
            .unwrap();

        // Now both are in the room
        assert_eq!(
            room_state.joined_users(),
            vec!["@bob:phnx.im".to_owned(), "@owner:phnx.im".to_owned()]
        );

        // @bob has the default role: Restricted
        assert!(room_state
            .user_roles
            .get("@bob:phnx.im")
            .unwrap()
            .contains(&RoleIndex::Restricted));

        // Visitors can only read, not send
        assert_eq!(
            room_state.make_actions(
                "@bob:phnx.im",
                &[Action::SendMessage {
                    message_type: MessageType::Image,
                }],
            ),
            Err(Error::NotCapable)
        );

        // The owner promotes @bob to a regular user
        room_state
            .make_actions(
                "@owner:phnx.im",
                &[Action::GiveRole {
                    target: "@bob:phnx.im".to_owned(),
                    role: RoleIndex::Regular,
                }],
            )
            .unwrap();

        // @bob can send messages now
        room_state
            .make_actions(
                "@bob:phnx.im",
                &[Action::SendMessage {
                    message_type: MessageType::Image,
                }],
            )
            .unwrap();

        // The owner can kick @bob, removing all the roles
        room_state
            .make_actions(
                "@owner:phnx.im",
                &[Action::Kick {
                    target: "@bob:phnx.im".to_owned(),
                }],
            )
            .unwrap();

        // Only the owner is in the room
        assert_eq!(room_state.joined_users(), vec!["@owner:phnx.im".to_owned()]);
    }

    #[test]
    fn edit_messages() {
        let mut room_state = test_room();

        // Editing own message is allowed
        room_state
            .make_actions(
                "@regular:phnx.im",
                &[Action::EditMessage {
                    target: "@regular:phnx.im".to_owned(),
                }],
            )
            .unwrap();

        // Editing other users' messages is usually not allowed
        assert_eq!(
            room_state.make_actions(
                "@regular:phnx.im",
                &[Action::EditMessage {
                    target: "@visitor:phnx.im".to_owned(),
                }],
            ),
            Err(Error::NotCapable)
        );

        // Moderators can edit other users' messages
        room_state
            .make_actions(
                "@mod:phnx.im",
                &[Action::EditMessage {
                    target: "@regular:phnx.im".to_owned(),
                }],
            )
            .unwrap();
    }

    #[test]
    fn leave_room() {
        let mut room_state = test_room();

        room_state
            .make_actions(
                "@mod:phnx.im",
                &[Action::Kick {
                    target: "@mod:phnx.im".to_owned(),
                }],
            )
            .unwrap();
    }

    #[test]
    fn kick_can_rejoin() {
        let mut room_state = test_room();

        // Mod kicks regular
        room_state
            .make_actions(
                "@mod:phnx.im",
                &[Action::Kick {
                    target: "@regular:phnx.im".to_owned(),
                }],
            )
            .unwrap();

        // Can rejoin
        room_state
            .make_actions(
                "@regular:phnx.im",
                &room_state.join_room_actions("@regular:phnx.im").unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn user_not_in_room() {
        let mut room_state = test_room();

        assert_eq!(
            room_state.make_actions(
                "@owner:phnx.im",
                &[Action::Kick {
                    target: "@notfound".to_owned(),
                }],
            ),
            Err(Error::UserNotInRoom)
        );
    }

    #[test]
    fn banned_cannot_rejoin() {
        let mut room_state = test_room();

        // Send spam
        room_state
            .make_actions(
                "@regular:phnx.im",
                &[Action::SendMessage {
                    message_type: MessageType::Image,
                }],
            )
            .unwrap();

        // Ban for spamming
        room_state
            .make_actions(
                "@owner:phnx.im",
                &[Action::Ban {
                    target: "@regular:phnx.im".to_owned(),
                    reason: "Spam".to_owned(),
                    until: None,
                }],
            )
            .unwrap();

        // Cannot spam anymore
        assert_eq!(
            room_state.make_actions(
                "@regular:phnx.im",
                &[Action::SendMessage {
                    message_type: MessageType::Image,
                }],
            ),
            Err(Error::Banned)
        );

        // Cannot spam anymore
        assert_eq!(
            room_state.make_actions(
                "@regular:phnx.im",
                &[Action::SendMessage {
                    message_type: MessageType::Image,
                }],
            ),
            Err(Error::Banned)
        );

        // Cannot invite
        assert_eq!(
            room_state.make_actions(
                "@owner:phnx.im",
                &[Action::GiveRole {
                    target: "@regular:phnx.im".to_owned(),
                    role: RoleIndex::Restricted
                }],
            ),
            Err(Error::Banned)
        );

        // Cannot rejoin
        assert_eq!(
            room_state.make_actions(
                "@regular:phnx.im",
                &room_state.join_room_actions("@regular:phnx.im").unwrap(),
            ),
            Err(Error::Banned)
        );
    }
}
