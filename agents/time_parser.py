"""Time-based rule parser for AFO.

Parses natural language time expressions into cron-like schedules
and time ranges for firewall rules.
"""

import re
from dataclasses import dataclass
from datetime import datetime, time
from enum import Enum


class DayOfWeek(Enum):
    """Days of the week."""
    MONDAY = 0
    TUESDAY = 1
    WEDNESDAY = 2
    THURSDAY = 3
    FRIDAY = 4
    SATURDAY = 5
    SUNDAY = 6


@dataclass
class TimeRange:
    """Represents a time range (e.g., 9am-5pm)."""
    start_hour: int
    start_minute: int
    end_hour: int
    end_minute: int

    def to_cron_hours(self) -> str:
        """Convert to cron hour expression."""
        if self.start_hour == self.end_hour:
            return str(self.start_hour)
        return f"{self.start_hour}-{self.end_hour}"

    def __str__(self) -> str:
        """Human-readable format."""
        return f"{self.start_hour:02d}:{self.start_minute:02d}-{self.end_hour:02d}:{self.end_minute:02d}"


@dataclass
class TimeSchedule:
    """Represents a complete time-based schedule."""
    time_range: TimeRange | None = None
    days_of_week: list[DayOfWeek] | None = None  # None = all days
    description: str = ""

    def to_cron(self) -> str:
        """
        Convert to cron expression.

        Format: minute hour day month day_of_week
        """
        minute = "0"  # Default to top of hour
        hour = "*"
        day = "*"
        month = "*"
        dow = "*"

        if self.time_range:
            hour = self.time_range.to_cron_hours()
            if self.time_range.start_minute > 0:
                minute = str(self.time_range.start_minute)

        if self.days_of_week:
            dow = ",".join(str(d.value) for d in self.days_of_week)

        return f"{minute} {hour} {day} {month} {dow}"

    def __str__(self) -> str:
        """Human-readable format."""
        parts = []
        if self.time_range:
            parts.append(str(self.time_range))
        if self.days_of_week:
            day_names = [d.name.capitalize() for d in self.days_of_week]
            parts.append(", ".join(day_names))
        return " on ".join(parts) if parts else "Always"


class TimeParser:
    """Parses natural language time expressions."""

    def __init__(self):
        # Common time expressions
        self.time_patterns = {
            # Business hours
            r'\b(?:business|office|work(?:ing)?)\s+hours?\b': TimeRange(9, 0, 17, 0),
            r'\b9\s*(?:am|a\.m\.)?\s*(?:to|-)\s*5\s*(?:pm|p\.m\.)?\b': TimeRange(9, 0, 17, 0),
            r'\b9\s*(?:am|a\.m\.)?\s*(?:to|-)\s*6\s*(?:pm|p\.m\.)?\b': TimeRange(9, 0, 18, 0),

            # Specific times
            r'\b(\d{1,2})\s*(?:am|a\.m\.)\s*(?:to|-)\s*(\d{1,2})\s*(?:pm|p\.m\.)\b': 'parse_am_pm',
            r'\b(\d{1,2}):(\d{2})\s*(?:to|-)\s*(\d{1,2}):(\d{2})\b': 'parse_24h',

            # After/before
            r'\bafter\s+(\d{1,2})\s*(?:pm|p\.m\.)\b': 'parse_after',
            r'\bbefore\s+(\d{1,2})\s*(?:am|a\.m\.)\b': 'parse_before',
        }

        # Day patterns
        self.day_patterns = {
            r'\bweekends?\b': [DayOfWeek.SATURDAY, DayOfWeek.SUNDAY],
            r'\bweekdays?\b': [DayOfWeek.MONDAY, DayOfWeek.TUESDAY, DayOfWeek.WEDNESDAY,
                               DayOfWeek.THURSDAY, DayOfWeek.FRIDAY],
            r'\bmondays?\b': [DayOfWeek.MONDAY],
            r'\btuesdays?\b': [DayOfWeek.TUESDAY],
            r'\bwednesdays?\b': [DayOfWeek.WEDNESDAY],
            r'\bthursdays?\b': [DayOfWeek.THURSDAY],
            r'\bfridays?\b': [DayOfWeek.FRIDAY],
            r'\bsaturdays?\b': [DayOfWeek.SATURDAY],
            r'\bsundays?\b': [DayOfWeek.SUNDAY],
        }

    def parse(self, text: str) -> TimeSchedule | None:
        """
        Parse time expression from text.

        Args:
            text: Natural language text containing time expression

        Returns:
            TimeSchedule object or None if no time expression found
        """
        text_lower = text.lower()

        # Parse time range
        time_range = self._parse_time_range(text_lower)

        # Parse days of week
        days = self._parse_days(text_lower)

        # If we found either time or days, return a schedule
        if time_range or days:
            description = self._generate_description(time_range, days)
            return TimeSchedule(
                time_range=time_range,
                days_of_week=days,
                description=description
            )

        return None

    def _parse_time_range(self, text: str) -> TimeRange | None:
        """Parse time range from text."""
        for pattern, value in self.time_patterns.items():
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                if isinstance(value, TimeRange):
                    return value
                elif value == 'parse_am_pm':
                    # Parse "9am to 5pm" style
                    start = int(match.group(1))
                    end = int(match.group(2))
                    # Convert PM to 24h
                    if end < 12:
                        end += 12
                    return TimeRange(start, 0, end, 0)
                elif value == 'parse_24h':
                    # Parse "09:00 to 17:00" style
                    return TimeRange(
                        int(match.group(1)),
                        int(match.group(2)),
                        int(match.group(3)),
                        int(match.group(4))
                    )
                elif value == 'parse_after':
                    # Parse "after 11pm"
                    hour = int(match.group(1))
                    if hour < 12:
                        hour += 12
                    return TimeRange(hour, 0, 23, 59)
                elif value == 'parse_before':
                    # Parse "before 6am"
                    hour = int(match.group(1))
                    return TimeRange(0, 0, hour, 0)

        return None

    def _parse_days(self, text: str) -> list[DayOfWeek] | None:
        """Parse days of week from text."""
        for pattern, days in self.day_patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                return days
        return None

    def _generate_description(self, time_range: TimeRange | None, days: list[DayOfWeek] | None) -> str:
        """Generate human-readable description."""
        parts = []

        if time_range:
            start = f"{time_range.start_hour:02d}:{time_range.start_minute:02d}"
            end = f"{time_range.end_hour:02d}:{time_range.end_minute:02d}"
            parts.append(f"{start} to {end}")

        if days:
            if len(days) == 2 and DayOfWeek.SATURDAY in days and DayOfWeek.SUNDAY in days:
                parts.append("on weekends")
            elif len(days) == 5 and DayOfWeek.SATURDAY not in days and DayOfWeek.SUNDAY not in days:
                parts.append("on weekdays")
            else:
                day_names = [d.name.capitalize() for d in days]
                parts.append(f"on {', '.join(day_names)}")

        return " ".join(parts) if parts else "Always active"


# Global instance
_time_parser: TimeParser | None = None


def get_time_parser() -> TimeParser:
    """Get or create the global time parser."""
    global _time_parser
    if _time_parser is None:
        _time_parser = TimeParser()
    return _time_parser


def parse_time_expression(text: str) -> TimeSchedule | None:
    """
    Parse time expression from text.

    Args:
        text: Natural language text

    Returns:
        TimeSchedule or None
    """
    parser = get_time_parser()
    return parser.parse(text)


# Example usage and tests
if __name__ == "__main__":
    test_cases = [
        "block social media during business hours",
        "allow database access between 12am and 4am",
        "restrict gaming traffic on weekends",
        "block outbound after 11pm except for admin",
        "allow SSH only during office hours on weekdays",
        "block port 80 from 9am to 6pm",
    ]

    parser = TimeParser()
    for test in test_cases:
        schedule = parser.parse(test)
        if schedule:
            print(f"Input: {test}")
            print(f"  Schedule: {schedule}")
            print(f"  Cron: {schedule.to_cron()}")
            print()
