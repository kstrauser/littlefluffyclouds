//! Little Fluffy Clouds (lfc) - IP Network Aggregation Tool
//!
//! This tool reads IP networks in CIDR notation from stdin and outputs an aggregated,
//! minimized list of networks. It combines adjacent networks that can be merged into
//! larger CIDR blocks and removes overlapping or duplicate entries.
//!
//! # Usage
//!
//! ```bash
//! cat networks.txt | lfc
//! ```
//!
//! # Input Format
//!
//! Each line should contain a single IP network in CIDR notation:
//! - IPv4: `192.168.1.0/24`
//! - IPv6: `2001:db8::/32`
//!
//! Empty lines and whitespace are ignored.
//!
//! # Output
//!
//! The aggregated networks are printed to stdout, one per line, sorted and minimized.
//!
//! # Examples
//!
//! Input:
//! ```text
//! 192.168.0.0/24
//! 192.168.1.0/24
//! 10.0.0.0/16
//! 10.0.1.0/24
//! ```
//!
//! Output:
//! ```text
//! 10.0.0.0/16
//! 192.168.0.0/23
//! ```

use ipnet::IpNet;
use std::{env, io, str};

/// Parses lines of text into IP networks in CIDR notation.
///
/// Each line should contain a single IP network (e.g., "192.168.1.0/24").
/// Empty lines and surrounding whitespace are ignored. If any line cannot
/// be parsed as a valid IP network, the function panics to prevent silent
/// failures that could lead to incorrect firewall rules or other security issues.
///
/// # Panics
///
/// Panics if any non-empty line cannot be parsed as a valid IP network.
///
/// # Examples
///
/// ```
/// let input = "192.168.1.0/24\n10.0.0.0/8";
/// let nets = parse_nets(input.lines());
/// assert_eq!(nets.len(), 2);
/// ```
fn parse_nets(lines: str::Lines) -> Vec<IpNet> {
    lines
        // Remove any surrounding whitespace from each line.
        .map(|line| line.trim()) //.to_string())
        // Skip empty lines.
        .filter(|line| !line.is_empty())
        // Parse each line as an IP network. Fail if any line is invalid because
        // that could give unexpected results. Imagine this is creating firewall
        // rules and the user accidentally typed an IP address instead of a
        // CIDR. Then we might be outputting a set of blocked addresses without
        // the one the user explicitly wanted to block! That's not good. It's
        // better here to say, hey, there's a problem with your input that you
        // need to fix before we can help you.
        .map(|line| match line.parse::<IpNet>() {
            Ok(net) => net,
            Err(_) => {
                panic!("Unable to parse {:?} as an IP network.", line)
            }
        })
        .collect()
}

/// Aggregates and merges IP networks to their minimal representation.
///
/// Takes a collection of IP networks and combines adjacent or overlapping networks
/// into larger CIDR blocks where possible. This process:
/// - Removes duplicate networks
/// - Merges overlapping networks (subnets absorbed by supernets)
/// - Combines adjacent networks that align on CIDR boundaries
/// - Preserves networks that cannot be aggregated
///
/// # Examples
///
/// ```
/// // Adjacent networks merge into a larger block
/// let nets = vec!["192.168.0.0/24".parse().unwrap(), "192.168.1.0/24".parse().unwrap()];
/// let result = gather(&nets);
/// assert_eq!(result, vec!["192.168.0.0/23".parse().unwrap()]);
///
/// // Overlapping networks are reduced to the supernet
/// let nets = vec!["10.0.0.0/16".parse().unwrap(), "10.0.1.0/24".parse().unwrap()];
/// let result = gather(&nets);
/// assert_eq!(result, vec!["10.0.0.0/16".parse().unwrap()]);
/// ```
fn gather(nets: &Vec<IpNet>) -> Vec<IpNet> {
    IpNet::aggregate(nets)
}

fn print_help() {
    print!(
        "\
Little Fluffy Clouds (lfc) - IP Network Aggregation Tool

USAGE:
    lfc [OPTIONS]

OPTIONS:
    -h, --help    Print help information

DESCRIPTION:
    Reads IP networks in CIDR notation from stdin and outputs an aggregated,
    minimized list of networks. Adjacent networks are merged into larger CIDR
    blocks where possible, and overlapping or duplicate entries are removed.

EXAMPLES:
    cat networks.txt | lfc
    echo -e '192.168.0.0/24\\n192.168.1.0/24' | lfc
"
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 {
        let arg = &args[1];
        if arg == "-h" || arg == "--help" {
            print_help();
            return;
        } else {
            eprintln!("error: unrecognized argument '{}'", arg);
            eprintln!();
            eprintln!("Usage: lfc [OPTIONS]");
            eprintln!();
            eprintln!("For more information, try '--help'.");
            std::process::exit(1);
        }
    }

    let stdin_contents = io::read_to_string(io::stdin()).unwrap();
    let nets = parse_nets(stdin_contents.lines());

    for n in gather(&nets) {
        println!("{}", n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nets_single_network() {
        let input = "192.168.1.0/24";
        let result = parse_nets(input.lines());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "192.168.1.0/24");
    }

    #[test]
    fn test_parse_nets_multiple_networks() {
        let input = "192.168.1.0/24\n10.0.0.0/8\n172.16.0.0/12";
        let result = parse_nets(input.lines());
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].to_string(), "192.168.1.0/24");
        assert_eq!(result[1].to_string(), "10.0.0.0/8");
        assert_eq!(result[2].to_string(), "172.16.0.0/12");
    }

    #[test]
    fn test_parse_nets_with_whitespace() {
        let input = "  192.168.1.0/24  \n  10.0.0.0/8  ";
        let result = parse_nets(input.lines());
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].to_string(), "192.168.1.0/24");
        assert_eq!(result[1].to_string(), "10.0.0.0/8");
    }

    #[test]
    fn test_parse_nets_with_empty_lines() {
        let input = "192.168.1.0/24\n\n10.0.0.0/8\n\n\n172.16.0.0/12";
        let result = parse_nets(input.lines());
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_parse_nets_ipv6() {
        let input = "2001:db8::/32\nfe80::/10";
        let result = parse_nets(input.lines());
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].to_string(), "2001:db8::/32");
        assert_eq!(result[1].to_string(), "fe80::/10");
    }

    #[test]
    fn test_parse_nets_mixed_ipv4_ipv6() {
        let input = "192.168.1.0/24\n2001:db8::/32";
        let result = parse_nets(input.lines());
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].to_string(), "192.168.1.0/24");
        assert_eq!(result[1].to_string(), "2001:db8::/32");
    }

    #[test]
    #[should_panic(expected = "Unable to parse")]
    fn test_parse_nets_invalid_input() {
        let input = "not-an-ip-address";
        parse_nets(input.lines());
    }

    #[test]
    #[should_panic(expected = "Unable to parse")]
    fn test_parse_nets_ip_without_cidr() {
        let input = "192.168.1.1";
        parse_nets(input.lines());
    }

    #[test]
    fn test_parse_nets_empty_input() {
        let input = "";
        let result = parse_nets(input.lines());
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_gather_overlapping_networks() {
        let nets = vec![
            "10.0.0.0/16".parse().unwrap(),
            "10.0.1.0/24".parse().unwrap(),
            "10.0.2.0/24".parse().unwrap(),
        ];
        let result = gather(&nets);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "10.0.0.0/16");
    }

    #[test]
    fn test_gather_adjacent_networks() {
        let nets = vec![
            "192.168.0.0/24".parse().unwrap(),
            "192.168.1.0/24".parse().unwrap(),
        ];
        let result = gather(&nets);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "192.168.0.0/23");
    }

    #[test]
    fn test_gather_four_adjacent_networks() {
        let nets = vec![
            "10.0.0.0/24".parse().unwrap(),
            "10.0.1.0/24".parse().unwrap(),
            "10.0.2.0/24".parse().unwrap(),
            "10.0.3.0/24".parse().unwrap(),
        ];
        let result = gather(&nets);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "10.0.0.0/22");
    }

    #[test]
    fn test_gather_non_adjacent_networks() {
        let nets = vec![
            "192.168.1.0/24".parse().unwrap(),
            "192.168.3.0/24".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];
        let result = gather(&nets);
        assert_eq!(result.len(), 3);
        assert!(result.contains(&"10.0.0.0/8".parse().unwrap()));
        assert!(result.contains(&"192.168.1.0/24".parse().unwrap()));
        assert!(result.contains(&"192.168.3.0/24".parse().unwrap()));
    }

    #[test]
    fn test_gather_duplicate_networks() {
        let nets = vec![
            "192.168.1.0/24".parse().unwrap(),
            "192.168.1.0/24".parse().unwrap(),
            "192.168.1.0/24".parse().unwrap(),
        ];
        let result = gather(&nets);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "192.168.1.0/24");
    }

    #[test]
    fn test_gather_ipv6_adjacent() {
        let nets = vec![
            "2001:db8::/33".parse().unwrap(),
            "2001:db8:8000::/33".parse().unwrap(),
        ];
        let result = gather(&nets);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "2001:db8::/32");
    }

    #[test]
    fn test_gather_ipv6_non_adjacent() {
        let nets = vec![
            "2001:db8::/32".parse().unwrap(),
            "2001:dba::/32".parse().unwrap(),
        ];
        let result = gather(&nets);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_gather_mixed_ipv4_ipv6() {
        let nets = vec![
            "192.168.0.0/24".parse().unwrap(),
            "192.168.1.0/24".parse().unwrap(),
            "2001:db8::/33".parse().unwrap(),
            "2001:db8:8000::/33".parse().unwrap(),
        ];
        let result = gather(&nets);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&"192.168.0.0/23".parse().unwrap()));
        assert!(result.contains(&"2001:db8::/32".parse().unwrap()));
    }

    #[test]
    fn test_gather_empty() {
        let nets = vec![];
        let result = gather(&nets);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_gather_single_network() {
        let nets = vec!["10.0.0.0/8".parse().unwrap()];
        let result = gather(&nets);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "10.0.0.0/8");
    }

    #[test]
    fn test_gather_complex_aggregation() {
        let nets = vec![
            "192.168.0.0/25".parse().unwrap(),
            "192.168.0.128/25".parse().unwrap(),
            "192.168.1.0/25".parse().unwrap(),
            "192.168.1.128/25".parse().unwrap(),
        ];
        let result = gather(&nets);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].to_string(), "192.168.0.0/23");
    }

    #[test]
    fn test_gather_alignment_issues() {
        let nets = vec![
            "30.0.33.0/24".parse().unwrap(),
            "30.0.34.0/24".parse().unwrap(),
            "10.0.7.0/24".parse().unwrap(),
            "10.0.8.0/24".parse().unwrap(),
            "10.0.9.0/24".parse().unwrap(),
            "20.0.14.0/23".parse().unwrap(),
            "20.0.16.0/23".parse().unwrap(),
            "20.0.18.0/23".parse().unwrap(),
            "20.0.20.0/23".parse().unwrap(),
            "30.0.32.0/20".parse().unwrap(),
        ];
        let result = gather(&nets);
        assert_eq!(result.len(), 6);
        assert!(result.contains(&"10.0.7.0/24".parse().unwrap()));
        assert!(result.contains(&"10.0.8.0/23".parse().unwrap()));
        assert!(result.contains(&"20.0.14.0/23".parse().unwrap()));
        assert!(result.contains(&"20.0.16.0/22".parse().unwrap()));
        assert!(result.contains(&"20.0.20.0/23".parse().unwrap()));
        assert!(result.contains(&"30.0.32.0/20".parse().unwrap()));
    }
}
