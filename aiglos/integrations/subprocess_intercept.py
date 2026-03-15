_session_events = []


class AiglosPauseTimeout(Exception):
    pass


def get_session_subprocess_events():
    return list(_session_events)


def clear_session_subprocess_events():
    _session_events.clear()


def subprocess_intercept_status():
    return {"active": True, "events": len(_session_events)}
