//! A server's load: a command that collects the numbers from `/proc` and `df`, and reading its output.
//!
//! Only works on Linux. The counters for CPU time and network rise from the server's start; the load
//! only follows from two measurements in a row. The computing is left to the caller.

/// Collects everything in one call. Every section starts with a line `@name`. Runs in `sh` so the
/// user's login shell (fish, csh) does not matter; whatever is missing simply stays empty.
pub const COMMAND: &str = concat!(
    "sh -c '",
    // Error messages (missing files on other systems) do not belong in the output.
    "exec 2>/dev/null; ",
    "echo @cpu; head -n 1 /proc/stat; ",
    "echo @cores; grep -c ^processor /proc/cpuinfo; ",
    "echo @mem; grep -E \"^(MemTotal|MemAvailable|MemFree|Buffers|Cached|SwapTotal|SwapFree):\" /proc/meminfo; ",
    "echo @load; cat /proc/loadavg; ",
    "echo @uptime; cat /proc/uptime; ",
    "echo @net; cat /proc/net/dev; ",
    "echo @disk; df -P -k; ",
    "echo @kernel; uname -r; ",
    "echo @host; hostname || cat /proc/sys/kernel/hostname; ",
    "echo @os; cat /etc/os-release",
    "'"
);

/// The display shows no more disks than this.
const MAX_DISKS: usize = 6;

#[derive(Debug, Clone, PartialEq)]
pub struct Disk {
    pub mount: String,
    pub device: String,
    /// Size and usage in bytes.
    pub total: u64,
    pub used: u64,
}

/// One measurement. Memory in bytes, CPU time in ticks since the start, network in bytes since the start.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub cpu_total: u64,
    pub cpu_idle: u64,
    pub cores: u32,
    pub mem_total: u64,
    pub mem_available: u64,
    pub swap_total: u64,
    pub swap_free: u64,
    pub load: [f64; 3],
    pub disks: Vec<Disk>,
    pub net_rx: u64,
    pub net_tx: u64,
    /// Seconds since the start.
    pub uptime: u64,
    /// Name of the system, e.g. “Ubuntu 24.04.1 LTS”.
    pub system: String,
    pub kernel: String,
    pub hostname: String,
}

/// File systems that do not mean space on a disk.
fn pseudo(device: &str, mount: &str) -> bool {
    const DEVICES: [&str; 12] = ["tmpfs", "devtmpfs", "udev", "overlay", "shm", "none", "efivarfs", "squashfs", "cgroup", "cgroup2", "run", "dev"];
    const MOUNTS: [&str; 7] = ["/dev", "/proc", "/sys", "/run", "/snap", "/boot", "/var/lib/docker/overlay"];
    DEVICES.contains(&device) || device.starts_with("/dev/loop") || MOUNTS.iter().any(|prefix| mount == *prefix || mount.starts_with(&format!("{prefix}/")))
}

/// Reads the output of [`COMMAND`]. `None` if the server does not provide the numbers (no Linux, no `/proc`).
pub fn parse(text: &str) -> Option<Sample> {
    let mut sections: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
    let mut current = "";
    for line in text.lines() {
        match line.trim().strip_prefix('@') {
            Some(name) => current = name,
            None if !line.trim().is_empty() => sections.entry(current).or_default().push(line.trim()),
            None => {}
        }
    }
    let lines = |name: &str| sections.get(name).cloned().unwrap_or_default();
    let numbers = |line: &str| line.split_whitespace().filter_map(|part| part.parse::<u64>().ok()).collect::<Vec<_>>();

    // “cpu  user nice system idle iowait irq softirq steal guest guest_nice”; guest time is already contained in user and nice.
    let cpu = lines("cpu").into_iter().find(|line| line.starts_with("cpu "))?;
    let ticks = numbers(cpu);
    if ticks.len() < 4 {
        return None;
    }
    let cpu_total: u64 = ticks.iter().take(8).sum();
    let cpu_idle = ticks[3] + ticks.get(4).copied().unwrap_or(0);

    let mem = |name: &str| lines("mem").into_iter().find_map(|line| line.strip_prefix(name)?.strip_prefix(':')?.split_whitespace().next()?.parse::<u64>().ok()).map(|kib| kib * 1024);
    let mem_total = mem("MemTotal")?;
    // Very old kernels do not know `MemAvailable`; free plus buffers and cache comes close.
    let mem_available = mem("MemAvailable").unwrap_or_else(|| mem("MemFree").unwrap_or(0) + mem("Buffers").unwrap_or(0) + mem("Cached").unwrap_or(0)).min(mem_total);

    let mut load = [0.0; 3];
    if let Some(line) = lines("load").first() {
        for (slot, part) in load.iter_mut().zip(line.split_whitespace()) {
            *slot = part.parse().unwrap_or(0.0);
        }
    }

    // “eth0: rx_bytes rx_packets … (eight fields) tx_bytes …”; loopback does not count.
    let (mut net_rx, mut net_tx) = (0u64, 0u64);
    for line in lines("net") {
        let Some((name, rest)) = line.split_once(':') else { continue };
        let fields = numbers(rest);
        if name.trim() != "lo" && fields.len() >= 9 {
            net_rx += fields[0];
            net_tx += fields[8];
        }
    }

    // “Filesystem 1024-blocks Used Available Capacity Mounted on”. A device mounted several times counts once.
    let mut disks: Vec<Disk> = Vec::new();
    for line in lines("disk") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let (Some(device), Some(blocks), Some(used)) = (parts.first(), parts.get(1).and_then(|n| n.parse::<u64>().ok()), parts.get(2).and_then(|n| n.parse::<u64>().ok())) else { continue };
        let mount = parts.get(5..).map(|rest| rest.join(" ")).unwrap_or_default();
        if blocks == 0 || !mount.starts_with('/') || pseudo(device, &mount) {
            continue;
        }
        let disk = Disk { mount, device: device.to_string(), total: blocks * 1024, used: used * 1024 };
        match disks.iter_mut().find(|known| known.device == disk.device) {
            Some(known) if disk.mount.len() < known.mount.len() => *known = disk,
            Some(_) => {}
            None => disks.push(disk),
        }
    }
    // The root first, then the largest.
    disks.sort_by(|a, b| (b.mount == "/").cmp(&(a.mount == "/")).then(b.total.cmp(&a.total)).then(a.mount.cmp(&b.mount)));
    disks.truncate(MAX_DISKS);

    let os = lines("os");
    let quoted = |key: &str| os.iter().find_map(|line| line.strip_prefix(key)?.strip_prefix('=')).map(|value| value.trim_matches(['"', '\'']).to_string());
    let clean = |text: String| text.chars().filter(|c| !c.is_control()).take(120).collect::<String>();

    Some(Sample {
        cpu_total,
        cpu_idle,
        cores: lines("cores").first().and_then(|line| line.parse().ok()).filter(|n| *n > 0).unwrap_or(1),
        mem_total,
        mem_available,
        swap_total: mem("SwapTotal").unwrap_or(0),
        swap_free: mem("SwapFree").unwrap_or(0),
        load,
        disks,
        net_rx,
        net_tx,
        uptime: lines("uptime").first().and_then(|line| line.split_whitespace().next()?.parse::<f64>().ok()).map_or(0, |seconds| seconds as u64),
        system: clean(quoted("PRETTY_NAME").or_else(|| quoted("NAME")).unwrap_or_default()),
        kernel: clean(lines("kernel").first().map(|line| line.to_string()).unwrap_or_default()),
        hostname: clean(lines("host").first().map(|line| line.to_string()).unwrap_or_default()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEBIAN: &str = "@cpu
cpu  41250 310 12840 9876543 2210 0 480 95 0 0
@cores
8
@mem
MemTotal:       16303412 kB
MemFree:         1203344 kB
MemAvailable:   10122108 kB
Buffers:          412300 kB
Cached:          8011220 kB
SwapTotal:       2097148 kB
SwapFree:        1912828 kB
@load
0.42 0.37 0.31 2/612 90211
@uptime
311402.18 2412876.11
@net
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 9912345   81234    0    0    0     0          0         0  9912345   81234    0    0    0     0       0          0
  eth0: 4200000000 3100000    0   12    0     0          0         0 910000000 2400000    0    0    0     0       0          0
docker0:  1000000    9000    0    0    0     0          0         0   5000000   11000    0    0    0     0       0          0
@disk
Filesystem     1024-blocks      Used Available Capacity Mounted on
udev               8126284         0   8126284       0% /dev
tmpfs              1630344      1312   1629032       1% /run
/dev/sda1         82436788  34512300  43701200      45% /
/dev/sda15          126678     11840    114838      10% /boot/efi
/dev/sdb1        206292968 165123400  30665420      85% /var/lib/docker
/dev/sdb1        206292968 165123400  30665420      85% /var/lib/docker/volumes/extra dir
overlay          206292968 165123400  30665420      85% /var/lib/docker/overlay2/abc/merged
/dev/loop3           65536     65536         0     100% /snap/core20/2318
nas:/export     1048576000 524288000 524288000      50% /mnt/nas
@kernel
6.8.0-45-generic
@host
web-01
@os
PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"
NAME=\"Ubuntu\"
VERSION_ID=\"24.04\"
";

    #[test]
    fn reads_a_typical_server() {
        let sample = parse(DEBIAN).unwrap();
        assert_eq!(sample.cpu_total, 41250 + 310 + 12840 + 9876543 + 2210 + 480 + 95);
        assert_eq!(sample.cpu_idle, 9876543 + 2210);
        assert_eq!(sample.cores, 8);
        assert_eq!((sample.mem_total, sample.mem_available), (16303412 * 1024, 10122108 * 1024));
        assert_eq!((sample.swap_total, sample.swap_free), (2097148 * 1024, 1912828 * 1024));
        assert_eq!(sample.load, [0.42, 0.37, 0.31]);
        assert_eq!(sample.uptime, 311402);
        assert_eq!((sample.net_rx, sample.net_tx), (4_201_000_000, 915_000_000), "die Schleife zählt nicht mit");
        assert_eq!((sample.system.as_str(), sample.kernel.as_str(), sample.hostname.as_str()), ("Ubuntu 24.04.1 LTS", "6.8.0-45-generic", "web-01"));
        let disks: Vec<(&str, u64)> = sample.disks.iter().map(|d| (d.mount.as_str(), d.total / 1024)).collect();
        assert_eq!(disks, [("/", 82436788), ("/mnt/nas", 1048576000), ("/var/lib/docker", 206292968)], "Wurzel zuerst, dann nach Größe; jedes Gerät einmal, ohne Scheindateisysteme");
        assert_eq!(sample.disks[0].used, 34512300 * 1024);
    }

    #[test]
    fn copes_with_old_kernels_zfs_and_missing_parts() {
        let text = "@cpu\ncpu 100 0 50 800\n@cores\n0\n@mem\nMemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 250 kB\n@disk\nFilesystem 1024-blocks Used Available Capacity Mounted on\nrpool/ROOT/pve-1 900000 100000 800000 12% /\nrpool/data 800000 96 799904 1% /rpool/data\n@os\nNAME=Alpine\n";
        let sample = parse(text).unwrap();
        assert_eq!((sample.cpu_total, sample.cpu_idle, sample.cores), (950, 800, 1));
        assert_eq!(sample.mem_available, 400 * 1024, "ohne MemAvailable: frei plus Puffer und Zwischenspeicher");
        assert_eq!(sample.disks.iter().map(|d| d.mount.as_str()).collect::<Vec<_>>(), ["/", "/rpool/data"], "ZFS-Datasets haben keinen Gerätepfad");
        assert_eq!((sample.system.as_str(), sample.kernel.as_str(), sample.uptime, sample.net_rx), ("Alpine", "", 0, 0));
    }

    #[test]
    fn other_systems_give_nothing() {
        // FreeBSD, macOS, Windows: no /proc, the sections stay empty.
        assert_eq!(parse("@cpu\n@cores\n@mem\n@load\n@uptime\n@net\n@disk\n@kernel\n14.1-RELEASE\n@host\nbsd\n@os\n"), None);
        assert_eq!(parse(""), None);
        assert_eq!(parse("'sh' is not recognized as an internal or external command"), None);
    }
}
