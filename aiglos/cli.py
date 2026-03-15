import sys
from aiglos.integrations.memory_guard import _score_memory_content


def _cmd_scan_message(args):
    if not args:
        print("Usage: aiglos scan-message <message_text>")
        return

    text = " ".join(args)
    score, risk, signals = _score_memory_content(text)

    if risk == "LOW" and not signals:
        print(f"CLEAN — risk={risk} score={score:.2f}")
    else:
        print(f"FLAGGED — risk={risk} score={score:.2f}")
        if signals:
            print(f"  signals: {', '.join(signals)}")
        if risk == "HIGH":
            print("  DO NOT store this content in agent memory.")
        elif risk == "MEDIUM":
            print("  Review before storing in agent memory.")


def _cmd_forecast(args):
    from aiglos.core.intent_predictor import IntentPredictor

    predictor = IntentPredictor()
    predictor.train()

    if not predictor.is_ready:
        print("No trained model found.  Run a few sessions first.")
        return

    if not args:
        stats = predictor.model_stats()
        print(f"Model: {stats['total_sessions']} sessions, "
              f"{stats['total_transitions']} transitions, "
              f"{stats['unique_states']} unique states.")
        return

    # replay a sequence of rule IDs and predict
    predictor.reset_session()
    for rule_id in args:
        predictor.observe(rule_id, "BLOCK")

    result = predictor.predict()
    if result is None:
        print("Not enough context for a prediction.")
        return

    print(f"Alert: {result.alert_level}  threshold={result.alert_threshold:.2%}")
    if result.top_threat:
        print(f"  top threat: {result.top_threat[0]}  p={result.top_threat[1]:.4f}")
    if result.secondary_threats:
        for name, p in result.secondary_threats:
            print(f"  secondary:  {name}  p={p:.4f}")


def main():
    if len(sys.argv) < 2:
        print("Usage: aiglos <command> [args]")
        print("Commands: scan-message, forecast")
        return

    cmd = sys.argv[1]
    if cmd == "scan-message":
        _cmd_scan_message(sys.argv[2:])
    elif cmd == "forecast":
        _cmd_forecast(sys.argv[2:])
    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
