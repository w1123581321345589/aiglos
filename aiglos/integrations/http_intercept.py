_session_events = []


def get_session_http_events():
    return list(_session_events)


def clear_session_http_events():
    _session_events.clear()


def http_intercept_status():
    return {"active": True, "events": len(_session_events)}
