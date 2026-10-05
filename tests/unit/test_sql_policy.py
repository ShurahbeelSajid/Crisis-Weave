from __future__ import annotations

import pytest

from crisisweave.security import SecurityError
from crisisweave.storage import validate_analytics_sql


def test_safe_aggregate_sql_is_bounded() -> None:
    result = validate_analytics_sql(
        "SELECT state, COUNT(*) AS event_count FROM authorized_storm_events "
        "WHERE begin_year = 2017 GROUP BY state ORDER BY 2 DESC",
        max_rows=25,
    )
    assert "LIMIT 25" in result
    assert "authorized_storm_events" in result

    lower_limit = validate_analytics_sql(
        "SELECT state FROM authorized_storm_events LIMIT 3", max_rows=25
    )
    assert "LIMIT 3" in lower_limit


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM authorized_storm_events; DROP TABLE storm_events",
        "ATTACH 'secret.db' AS secrets",
        "SELECT * FROM read_csv_auto('C:/secrets.txt')",
        "SELECT raw_json FROM authorized_storm_events",
        "SELECT episode_narrative FROM authorized_storm_events",
        "SELECT * FROM authorized_storm_events JOIN documents USING(document_id)",
        "SELECT * FROM authorized_storm_events",
        "WITH leaked AS (SELECT * FROM authorized_storm_events) SELECT * FROM leaked",
        "SELECT * FROM authorized_storm_events -- bypass",
        "SELECT current_setting('access_mode') FROM authorized_storm_events",
        "SELECT state AS raw_json, raw_json AS state FROM authorized_storm_events",
        "SELECT state AS tenant_id FROM authorized_storm_events",
        "SELECT DISTINCT state FROM authorized_storm_events",
        "SELECT COUNT(*) OVER () AS event_count FROM authorized_storm_events",
        "SELECT COUNT(*) FILTER (WHERE begin_year = 2017) AS event_count "
        "FROM authorized_storm_events",
        "SELECT SUM(begin_year = 2017) AS event_count FROM authorized_storm_events",
        "SELECT COUNT(begin_year = 2017 OR NULL) AS event_count FROM authorized_storm_events",
        "SELECT state AS __crisisweave_source_ids FROM authorized_storm_events",
        "SELECT state || state AS amplified FROM authorized_storm_events",
        "SELECT state, COUNT(*) FROM authorized_storm_events GROUP BY CUBE(state, event_type)",
        "SELECT state, COUNT(*) FROM authorized_storm_events GROUP BY ROLLUP(state, event_type)",
        "SELECT state, COUNT(*) FROM authorized_storm_events "
        "GROUP BY GROUPING SETS ((state), (event_type))",
        "SELECT state FROM authorized_storm_events USING SAMPLE 10",
        "SELECT state FROM authorized_storm_events OFFSET 100000",
        "SELECT state FROM authorized_storm_events LIMIT -1",
    ],
)
def test_unsafe_sql_is_rejected(sql: str) -> None:
    with pytest.raises(SecurityError):
        validate_analytics_sql(sql)
