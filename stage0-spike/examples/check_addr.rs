use stage0_spike::address::{validate_destination, Network};
fn main() {
    for a in std::env::args().skip(1) {
        for n in [Network::Mainnet, Network::Stagenet, Network::Testnet] {
            println!("{}.. net={:?} => {:?}", &a[..12], n, validate_destination(&a, n));
        }
    }
}
