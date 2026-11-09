//! Closed, exact bounded-prefix driver roles. No full-epoch promotion.
use crate::*;
pub const DRIVER10: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch185-guarded-adapter-v10/epoch185-guarded-cold";
pub const SHA10: &str = "0a7dddaaa5ae049a6a9f6ca103fd8463987d6aff52397a4ece09a43387107e1a";
pub const DRIVER11: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch185-guarded-adapter-v11/epoch185-guarded-cold";
pub const SHA11: &str = "bdadc547439d2dbba11797f715c1741772dad693cd54073ac273132a7ba096f2";
pub const DRIVER12: &str = "/usr/local/lib/jetstreamer/horizon-epoch185-guarded-adapter-v12/epoch185-guarded-cold";
pub const SHA12: &str = "b437ada8808ceae8d80a699fa2114446c735d7e72ae4d616fdead4646bb3082e";
pub fn supported(driver: &Bound) -> bool {
    [(DRIVER10, SHA10), (DRIVER11, SHA11), (DRIVER12, SHA12)]
        .iter()
        .any(|(path, sha)| driver.path == Path::new(path) && driver.sha256 == *sha)
}
pub fn historical(driver: &Bound) -> bool {
    driver.path == Path::new(DRIVER10) && driver.sha256 == SHA10
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_driver10_and11_roles_reject_crossed_and_unknown_images() {
        assert!(supported(&fixed(DRIVER10, SHA10)));
        assert!(supported(&fixed(DRIVER11, SHA11)));
        for b in [
            fixed(DRIVER10, SHA11),
            fixed(DRIVER11, SHA10),
            fixed("/tmp/epoch185-guarded-cold", SHA11),
            fixed(DRIVER11, &"a".repeat(64)),
        ] {
            assert!(!supported(&b));
        }
    }
}

#[cfg(test)] mod driver12_additive {use super::*;#[test]fn actual_driver12_does_not_borrow_historical_or_crossed_pairs(){assert!(supported(&fixed(DRIVER12,SHA12)));for value in [fixed(DRIVER12,SHA11),fixed(DRIVER11,SHA12),fixed(DRIVER12,SHA10),fixed("/tmp/driver12",SHA12)]{assert!(!supported(&value));}assert!(!historical(&fixed(DRIVER12,SHA12)));}}
