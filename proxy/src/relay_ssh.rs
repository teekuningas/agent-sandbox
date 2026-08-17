// Separate [[bin]] targets cannot share `mod` declarations, so this module is
// compiled independently for each binary.  The types are structurally identical
// but not the same Rust type.  This is fine because no types cross binary
// boundaries -- the wire format is the compatibility contract.
#[path = "relay_protocol.rs"]
mod relay_protocol;

#[path = "relay_client.rs"]
mod relay_client;

fn main() {
    relay_client::run_client(relay_protocol::CommandType::Ssh);
}
