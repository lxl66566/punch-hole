//! Strategy selection, burst sizing, and the shared punch engine.

mod birthday;
mod cone;
mod direct;
mod easy_sym;
mod engine;
mod model;
mod predictive_burst;
mod select;
mod sym_cone;

pub(crate) use engine::{Engine, Refresh, StageSpec};
pub(crate) use model::{
    PREDICTION_SLACK, burst_len, distinct_ports, peer_space, size_predictive, span_estimate,
    spray_count,
};
pub(crate) use select::{Selection, build_plan, effective_class, select};
