from datetime import datetime
from dateutil import parser

def format_datetime(date_format: str, scheduled_at):
    """
    Formats a datetime object or a string into the specified date format.

    Parameters:
        date_format (str): The format string to format the datetime.
        scheduled_at (datetime or str): The datetime object or string to format.

    Returns:
        str: The formatted datetime string.
    """
    if not isinstance(scheduled_at, datetime):
        scheduled_at = parser.parse(scheduled_at)

    return scheduled_at.strftime(date_format)


def convert_timestamp_to_utc(timestamp, format):
    my_datetime = datetime.utcfromtimestamp(timestamp)
    formatted_datetime = my_datetime.strftime(format)
    return formatted_datetime
