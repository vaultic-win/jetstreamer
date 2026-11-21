"""Run the original 172 publisher with the capacity provider that retains focused 169."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import full172_event
import retry10_event


def profile():
    previous = full172_event.profile()
    return previous._replace(launch=previous.delivery/"controller-tools-v2/run-committed.sh",
                             fit=previous.delivery/"capacity-tools-v2/publication-fit")


def main():
    retry10_event.main(profile(), recover=True, predecessors=((full172_event.profile(), "event-tools-current"),))


if __name__ == "__main__":
    if len(sys.argv) != 1:
        sys.exit("usage: focused169_full172_event.py")
    main()
