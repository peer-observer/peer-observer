use crate::protobuf::log_extractor::log::LogEvent;
use crate::protobuf::log_extractor::{
    BlockCheckedLog, BlockConnectedLog, Log, LogDebugCategory, UnknownLogMessage,
};
use lazy_static::lazy_static;
use regex::Regex;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const NANOS_PER_MICRO: i128 = 1_000;

/// Regular expression for matching RFC3339-compliant timestamps.
///
/// Matches a timestamp string with the following components:
/// - `\d{4}-\d{2}-\d{2}`: Matches a date in `YYYY-MM-DD` format (four digits for year, two for month, two for day).
/// - `T`: Matches the literal `T` separator between date and time.
/// - `\d{2}:\d{2}:\d{2}`: Matches a time in `HH:MM:SS` format (two digits each for hours, minutes, seconds).
/// - `(?:\.\d{1,6})?`: Optionally matches a fractional second part:
///   - `(?:...)`: Non-capturing group for the decimal part.
///   - `\.\d{1,6}`: Matches a decimal point followed by 1 to 6 digits.
/// - `Z`: Matches the literal `Z` indicating UTC timezone.
static RFC3339_DATE_PATTERN: &str = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z";

/// Regular expression to capture metadata inside square brackets `[...]`
/// (e.g., log category, thread name, function, etc.).
///
/// Captures: the content between `[` and `]`.
///
/// Breakdown:
/// - `\[`          literal `[`.
/// - `([^\]]+)`    capturing group: one or more characters except `]`.
/// - `\]`          literal `]`.
static METADATA_PATTERN: &str = r"\[([^\]]+)\]";

/// Regular expression for matching a 64-character hexadecimal block hash.
/// Matches strings consisting of exactly 64 characters in the range `0-9` or `a-f`.
static BLOCK_HASH_PATTERN: &str = r"[0-9a-f]{64}";

/// Regular expression for matching the output of `ValidationState::ToString()`.
///
/// Matches strings produced by the `ToString()` method of a validation state object:
/// - `(.*?)`: Captures the **primary reject reason**, non-greedily matching everything up to the first comma and space `", "` or the end of the string.
/// - `(?:,\s|$)`: Non-capturing group that matches either the separator `", "` or the end of the string.
/// - `(.+)?`: Optionally captures the **debug message** that follows the separator, if present.
static VALIDATION_STATE_PATTERN: &str = r"(.*?)(?:,\s|$)(.+)?";

lazy_static! {
    /// Regular expression for parsing default infos from log lines.
    ///
    /// Breakdown:
    /// - `^`                          : Start of line.
    /// - `(?P<timestamp>{})`          : Named capture for the timestamp (uses RFC3339_DATE_PATTERN).
    /// - `\s+`                        : One or more whitespace after timestamp.
    /// - `(?P<metadata>(?:{}\s+)*)`   : Named capture for metadata:
    ///   - `(?:{}\s+)*`               : Zero or more occurrences of METADATA_PATTERN followed by whitespace.
    /// - `(?P<message>.+)$`           : Named capture for the remaining message until end of line.
    static ref LOG_LINE_REGEX: Regex = {
        let pattern = format!(
            r"^(?P<timestamp>{})\s+(?P<metadata>(?:{}\s+)*)(?P<message>.+)$",
            RFC3339_DATE_PATTERN,
            METADATA_PATTERN
        );

        Regex::new(&pattern).unwrap()
    };

    static ref METADATA_REGEX: Regex = Regex::new(METADATA_PATTERN).unwrap();

    static ref BLOCK_CONNECTED_REGEX: Regex = Regex::new(&format!(
        r"BlockConnected: block hash=({}) block height=(\d+)",
        BLOCK_HASH_PATTERN
    ))
    .unwrap();

    static ref BLOCK_CHECKED_REGEX: Regex = Regex::new(&format!(
        r"BlockChecked: block hash=({}) state={}",
        BLOCK_HASH_PATTERN,
        VALIDATION_STATE_PATTERN
    ))
    .unwrap();
}

trait LogMatcher {
    fn parse_event(line: &str) -> Option<LogEvent>;
}

impl LogMatcher for UnknownLogMessage {
    fn parse_event(line: &str) -> Option<LogEvent> {
        Some(LogEvent::UnknownLogMessage(UnknownLogMessage {
            raw_message: line.to_string(),
        }))
    }
}

impl LogMatcher for BlockConnectedLog {
    fn parse_event(line: &str) -> Option<LogEvent> {
        let caps = BLOCK_CONNECTED_REGEX.captures(line)?;

        let block_hash = caps.get(1)?.as_str().to_string();
        let block_height = caps.get(2)?.as_str().parse::<u32>().ok()?;
        Some(LogEvent::BlockConnectedLog(BlockConnectedLog {
            block_hash,
            block_height,
        }))
    }
}

impl LogMatcher for BlockCheckedLog {
    fn parse_event(line: &str) -> Option<LogEvent> {
        let caps = BLOCK_CHECKED_REGEX.captures(line)?;

        let block_hash = caps.get(1)?.as_str().to_string();
        let state = caps.get(2)?.as_str().to_string();
        let debug_message = caps
            .get(3)
            .map_or_else(String::new, |m| m.as_str().to_string());
        Some(LogEvent::BlockCheckedLog(BlockCheckedLog {
            block_hash,
            state,
            debug_message,
        }))
    }
}

impl BlockCheckedLog {
    pub fn is_mutated_block(&self) -> bool {
        matches!(
            self.state.as_str(),
            "bad-txnmrklroot"
                | "bad-txns-duplicate"
                | "bad-witness-nonce-size"
                | "bad-witness-merkle-match"
                | "unexpected-witness"
        )
    }
}

pub fn parse_log_event(line: &str) -> Log {
    let CommonLogData {
        timestamp_micro,
        category,
        threadname,
        message,
    } = parse_common_log_data(line);

    let matchers: Vec<fn(&str) -> Option<LogEvent>> =
        vec![BlockConnectedLog::parse_event, BlockCheckedLog::parse_event];
    for matcher in &matchers {
        if let Some(event) = matcher(&message) {
            return Log {
                log_timestamp: timestamp_micro,
                category: category.into(),
                threadname,
                log_event: Some(event),
            };
        }
    }

    // if no matcher succeeds, return unknown
    Log {
        log_timestamp: timestamp_micro,
        category: category.into(),
        threadname,
        log_event: UnknownLogMessage::parse_event(&message),
    }
}

struct CommonLogData {
    pub timestamp_micro: u64,
    pub category: LogDebugCategory,
    pub threadname: String,
    pub message: String,
}

fn parse_common_log_data(line: &str) -> CommonLogData {
    let caps = LOG_LINE_REGEX.captures(line);
    if caps.is_none() {
        return CommonLogData {
            timestamp_micro: 0,
            category: LogDebugCategory::Unknown,
            threadname: String::new(),
            message: String::new(),
        };
    }

    let caps = caps.unwrap();

    let timestamp_str = &caps["timestamp"];
    let timestamp_nano = match OffsetDateTime::parse(timestamp_str, &Rfc3339) {
        Ok(dt) => dt.unix_timestamp_nanos(),
        Err(_) => 0,
    };
    let timestamp_micro = (timestamp_nano / NANOS_PER_MICRO) as u64;

    let metadata = caps
        .name("metadata")
        .map(|m| m.as_str())
        .unwrap_or_else(|| "");
    let mut metadata_items: Vec<String> = METADATA_REGEX
        .captures_iter(metadata)
        .map(|cap| cap[1].to_string())
        .collect();

    // if exists, category is usually the last metadata item
    let mut category = LogDebugCategory::Unknown;
    if let Some(last_item) = metadata_items.last() {
        if let Some(cat) = LogDebugCategory::from_str_name(&last_item.to_uppercase()) {
            category = cat;
            metadata_items.pop();
        }
    }

    // if exists, threadname is usually the first metadata item
    let threadname = metadata_items.first().cloned().unwrap_or_default();

    CommonLogData {
        timestamp_micro,
        category,
        threadname,
        message: caps["message"].to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_matcher_unknown_log_message() {
        let log = "2025-10-02T02:31:14Z Verification progress: 50%";
        let log_event = parse_log_event(log);

        assert_eq!(log_event.log_timestamp, 1759372274000000);
        assert_eq!(log_event.category, LogDebugCategory::Unknown as i32);
        assert_eq!(log_event.threadname, "");

        if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
            assert_eq!(unknown_log.raw_message, "Verification progress: 50%");
            return;
        }

        panic!("Expected UnknownLogMessage event");
    }

    #[test]
    fn test_log_matcher_unknown_log_message_with_category() {
        // debug (flags)
        let log = "2025-10-02T02:31:21Z [net] Flushed 0 addresses to peers.dat  2ms";
        let log_event = parse_log_event(log);

        assert_eq!(log_event.log_timestamp, 1759372281000000);
        assert_eq!(log_event.category, LogDebugCategory::Net as i32);

        if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
            assert_eq!(
                unknown_log.raw_message,
                "Flushed 0 addresses to peers.dat  2ms"
            );
            return;
        }

        panic!("Expected UnknownLogMessage event");
    }

    #[test]
    fn test_log_matcher_unknown_with_threadname() {
        // logthreadnames (flags)
        let log = "2025-12-23T22:38:01.977182Z [msghand] received: pong (8 bytes) peer=0";
        let log_event = parse_log_event(log);

        assert_eq!(log_event.threadname, "msghand".to_string());
        assert_eq!(log_event.category, LogDebugCategory::Unknown as i32);

        if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
            assert_eq!(unknown_log.raw_message, "received: pong (8 bytes) peer=0");
            return;
        }

        panic!("Expected UnknownLogMessage event");
    }

    #[test]
    fn test_log_matcher_unknown_with_threadname_and_category() {
        // logthreadnames + debug (flags)
        let log = "2025-12-23T22:38:01.977182Z [msghand] [net] received: pong (8 bytes) peer=0";
        let log_event = parse_log_event(log);

        assert_eq!(log_event.threadname, "msghand".to_string());
        assert_eq!(log_event.category, LogDebugCategory::Net as i32);

        if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
            assert_eq!(unknown_log.raw_message, "received: pong (8 bytes) peer=0");
            return;
        }

        panic!("Expected UnknownLogMessage event");
    }

    #[test]
    fn test_log_matcher_unknown_with_all_metadata() {
        // logthreadnames + logsourcelocations + debug (flags)
        let log = "2025-12-23T22:38:01.977182Z [msghand] [net_processing.cpp:3452] [ProcessMessage] [net] received: pong (8 bytes) peer=0";
        let log_event = parse_log_event(log);

        assert_eq!(log_event.threadname, "msghand".to_string());
        assert_eq!(log_event.category, LogDebugCategory::Net as i32);

        if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
            assert_eq!(unknown_log.raw_message, "received: pong (8 bytes) peer=0");
            return;
        }

        panic!("Expected UnknownLogMessage event");
    }

    #[test]
    fn test_log_matcher_block_connected_with_enqueuing() {
        let log = "2025-09-27T01:52:01Z [validation] Enqueuing BlockConnected: block hash=41109f31c8ca4d8683ab5571ba462292ddb8486dee6ecd2e62901accc7952f0b block height=437";
        let log_event = parse_log_event(log);

        assert_eq!(log_event.category, LogDebugCategory::Validation as i32);

        if let Some(LogEvent::BlockConnectedLog(event)) = log_event.log_event {
            assert_eq!(
                event.block_hash,
                "41109f31c8ca4d8683ab5571ba462292ddb8486dee6ecd2e62901accc7952f0b"
            );
            assert_eq!(event.block_height, 437);
            return;
        }

        panic!("Expected BlockConnectedLog event");
    }

    #[test]
    fn test_log_matcher_block_connected() {
        let log = "2025-09-27T01:52:01Z [validation] BlockConnected: block hash=6022a9138d879a9d525dba16a0e7d85eda9874736c1aed5c8da0c23ee878db4f block height=5";
        let log_event = parse_log_event(log);

        assert_eq!(log_event.category, LogDebugCategory::Validation as i32);

        if let Some(LogEvent::BlockConnectedLog(event)) = log_event.log_event {
            assert_eq!(
                event.block_hash,
                "6022a9138d879a9d525dba16a0e7d85eda9874736c1aed5c8da0c23ee878db4f"
            );
            assert_eq!(event.block_height, 5);
            return;
        }

        panic!("Expected BlockConnectedLog event");
    }

    #[test]
    fn test_log_matcher_with_logtimemicros_option() {
        let log = "2025-10-17T23:52:01.358911Z [validation] Random message";
        let log_event = parse_log_event(log);

        assert_eq!(log_event.log_timestamp, 1760745121358911);
        assert_eq!(log_event.category, LogDebugCategory::Validation as i32);

        if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
            assert_eq!(unknown_log.raw_message, "Random message");
            return;
        }
        panic!("Expected UnknownLogMessage event");
    }

    #[test]
    fn test_log_matcher_with_broken_timestamp() {
        let log = "2025--17T23:52:01.358911Z [validation] Random message";
        let log_event = parse_log_event(log);

        assert_eq!(log_event.log_timestamp, 0);
        assert_eq!(log_event.category, LogDebugCategory::Unknown as i32);

        if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
            assert_eq!(unknown_log.raw_message, "");
            return;
        }
        panic!("Expected UnknownLogMessage event");
    }

    #[test]
    fn test_log_matcher_with_broken_timestamp2() {
        let log = "2025-99-99T99:99:99.358911Z [validation] Random message";
        let log_event = parse_log_event(log);

        assert_eq!(log_event.log_timestamp, 0);
        assert_eq!(log_event.category, LogDebugCategory::Validation as i32);

        if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
            assert_eq!(unknown_log.raw_message, "Random message");
            return;
        }
        panic!("Expected UnknownLogMessage event");
    }

    #[test]
    fn test_log_matcher_with_unknown_category() {
        let log = "2025-22-17T23:52:01.358911Z [This-Is-N0t-a-valid-category] Random message";
        let log_event = parse_log_event(log);

        assert_eq!(log_event.log_timestamp, 0);
        assert_eq!(log_event.category, LogDebugCategory::Unknown as i32);

        if let Some(LogEvent::UnknownLogMessage(unknown_log)) = log_event.log_event {
            assert_eq!(unknown_log.raw_message, "Random message");
            return;
        }
        panic!("Expected UnknownLogMessage event");
    }

    #[test]
    fn test_log_matcher_block_checked() {
        let log = "2025-10-28T02:18:37Z [validation] BlockChecked: block hash=3909cd2a5ff36b9a40368609f92945e5b7111bca3cb4d04b72c39964aeb5d156 state=Valid";
        let log_event = parse_log_event(log);

        assert_eq!(log_event.log_timestamp, 1761617917000000);
        assert_eq!(log_event.category, LogDebugCategory::Validation as i32);

        if let Some(LogEvent::BlockCheckedLog(event)) = log_event.log_event {
            assert_eq!(
                event.block_hash,
                "3909cd2a5ff36b9a40368609f92945e5b7111bca3cb4d04b72c39964aeb5d156"
            );
            assert_eq!(event.state, "Valid");
            assert_eq!(event.debug_message, "");
            return;
        }
        panic!("Expected BlockCheckedLog event");
    }

    #[test]
    fn test_log_matcher_block_checked_with_debug_message() {
        let log = "2025-10-28T02:18:37Z [validation] BlockChecked: block hash=3909cd2a5ff36b9a40368609f92945e5b7111bca3cb4d04b72c39964aeb5d156 state=bad-txnmrklroot, hashMerkleRoot mismatch";
        let log_event = parse_log_event(log);

        assert_eq!(log_event.log_timestamp, 1761617917000000);
        assert_eq!(log_event.category, LogDebugCategory::Validation as i32);

        if let Some(LogEvent::BlockCheckedLog(event)) = log_event.log_event {
            assert_eq!(
                event.block_hash,
                "3909cd2a5ff36b9a40368609f92945e5b7111bca3cb4d04b72c39964aeb5d156"
            );
            assert_eq!(event.state, "bad-txnmrklroot");
            assert_eq!(event.debug_message, "hashMerkleRoot mismatch");
            return;
        }
        panic!("Expected BlockCheckedLog event");
    }
}
