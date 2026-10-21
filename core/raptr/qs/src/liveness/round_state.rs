use aptos_consensus_types::round_timeout::RoundTimeoutReason;
use serde::Serialize;
use std::fmt;
/// A reason for starting a new round: introduced for monitoring / debug purposes.
#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
pub enum NewRoundReason {
    QCReady,
    Timeout(RoundTimeoutReason),
}

impl fmt::Display for NewRoundReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NewRoundReason::QCReady => write!(f, "QCReady"),
            NewRoundReason::Timeout(_) => write!(f, "TCReady"),
        }
    }
}

