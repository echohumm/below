use {
    core::time::Duration,
    std::{collections::HashMap, net::IpAddr, time::Instant}
};

#[derive(Default)]
pub struct Entry {
    pub strikes: u32,
    pub last_strike: Option<Instant>,
    pub bans: u32, // how many times this IP has been banned (for escalation)
    pub banned_until: Option<Instant>
}

pub struct Blacklist {
    pub entries: HashMap<IpAddr, Entry>
}

const STRIKE_LIMIT: u32 = 3;
const STRIKE_WINDOW: Duration = Duration::from_mins(60);
const BAN_BASE: Duration = Duration::from_mins(15);
const BAN_MAX: Duration = Duration::from_hours(24);

// normalize so one client can't dodge bans by rotating addresses
pub fn key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            // ban by /64: a single host typically controls the whole prefix
            let mut o = v6.octets();
            o[8..].fill(0);
            IpAddr::V6(o.into())
        }
        v4 @ IpAddr::V4(_) => v4
    }
}

impl Blacklist {
    pub fn new() -> Blacklist {
        Blacklist { entries: HashMap::new() }
    }

    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.entries.get(&ip).and_then(|e| e.banned_until).is_some_and(|t| Instant::now() < t)
    }

    // records a failed attempt, returning true if a ban was triggered
    pub fn strike(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let e = self.entries.entry(ip).or_default();

        // prune before we strike
        if e.last_strike.is_some_and(|t| now.duration_since(t) > STRIKE_WINDOW) {
            e.strikes = 0;
        }
        e.strikes += 1;
        e.last_strike = Some(now);

        if e.strikes < STRIKE_LIMIT {
            return false;
        }

        // double bans up to BAN_MAX. starts at 15m
        let dur = BAN_BASE.saturating_mul(1 << e.bans.min(10)).min(BAN_MAX);
        e.banned_until = Some(now + dur);
        e.bans += 1;
        e.strikes = 0;
        true
    }

    // successful login, forgive strikes
    pub fn clear_strikes(&mut self, ip: IpAddr) {
        if let Some(e) = self.entries.get_mut(&ip) {
            e.strikes = 0;
        }
    }

    // remove ban state and strikes which have expired
    pub fn prune(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, e| {
            e.banned_until.is_some_and(|t| now < t)
                || e.last_strike.is_some_and(|t| now.duration_since(t) <= STRIKE_WINDOW)
        });
    }
}
