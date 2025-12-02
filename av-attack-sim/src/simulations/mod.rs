//! Attack simulation definitions.

mod advanced_evasion;
mod command_control;
mod credential_access;
mod defense_evasion;
mod discovery;
mod execution;
mod impact;
mod lateral_movement;
mod persistence;

use crate::framework::AttackSimulator;

pub fn register_all(simulator: &mut AttackSimulator) {
    execution::register(simulator);
    persistence::register(simulator);
    defense_evasion::register(simulator);
    credential_access::register(simulator);
    discovery::register(simulator);
    lateral_movement::register(simulator);
    command_control::register(simulator);
    impact::register(simulator);
    advanced_evasion::register(simulator);
}
