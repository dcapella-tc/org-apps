import argparse
import gzip
import os
import sys
from typing import TextIO


DEFAULT_INPUT = os.path.join("example", "Potentially Abused Domains (1).gz")
DEFAULT_OUTPUT = "sample_potentially_abused_domains.txt"


def sample_gz_lines(
    input_path: str,
    output_path: str,
    num_lines: int = 1000,
    force: bool = False,
    verbose: bool = False,
) -> int:
    """Sample the first ``num_lines`` lines from a large gzipped text file.

    The file is processed in a streaming, line-by-line fashion so that only a
    single line is held in memory at any time.

    Returns the number of lines actually written.
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Input file does not exist: {input_path}")

    if os.path.exists(output_path) and not force:
        raise FileExistsError(
            f"Output file already exists: {output_path} (use --force to overwrite)"
        )

    lines_written = 0

    def _log(msg: str) -> None:
        if verbose:
            print(msg, file=sys.stderr)

    _log(
        f"Reading from '{input_path}', writing up to {num_lines} lines to '{output_path}'"
    )

    # Open input gz file in text mode and output file in text mode.
    # Rely on default buffering for efficiency.
    with gzip.open(input_path, mode="rt", encoding="utf-8", errors="replace") as f_in, (
        open(output_path, mode="w", encoding="utf-8", newline="")
    ) as f_out:
        lines_written = _copy_lines(f_in, f_out, num_lines, _log)

    _log(f"Finished; wrote {lines_written} line(s).")
    return lines_written


def _copy_lines(
    source: TextIO,
    dest: TextIO,
    num_lines: int,
    log_fn,
) -> int:
    """Copy at most ``num_lines`` lines from ``source`` to ``dest``."""
    count = 0
    for line in source:
        dest.write(line)
        count += 1
        if count >= num_lines:
            break
    log_fn(f"Copied {count} line(s).")
    return count


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Sample the first N lines from a large gzipped text file into a "
            "plain-text output file, using streaming I/O to avoid high memory usage."
        )
    )
    parser.add_argument(
        "--input",
        "-i",
        default=DEFAULT_INPUT,
        help=f"Path to input .gz file (default: {DEFAULT_INPUT!r})",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=DEFAULT_OUTPUT,
        help=f"Path to output plain-text file (default: {DEFAULT_OUTPUT!r})",
    )
    parser.add_argument(
        "--num-lines",
        "-n",
        type=int,
        default=1000,
        help="Number of lines to sample from the input file (default: 1000).",
    )
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Allow overwriting an existing output file.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print basic progress information to stderr.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Examples
    --------
    - Use defaults (1,000 lines from the example .gz file):
        python sample_pad_file.py

    - Explicit paths and count:
        python sample_pad_file.py \\
            --input \"example/Potentially Abused Domains (1).gz\" \\
            --output sample_pad_1k.txt \\
            --num-lines 1000
    """
    args = parse_args(argv)

    if args.num_lines <= 0:
        print("--num-lines must be a positive integer.", file=sys.stderr)
        return 2

    try:
        written = sample_gz_lines(
            input_path=args.input,
            output_path=args.output,
            num_lines=args.num_lines,
            force=args.force,
            verbose=args.verbose,
        )
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return 1
    except FileExistsError as e:
        print(str(e), file=sys.stderr)
        return 1
    except gzip.BadGzipFile as e:
        print(f"Failed to read gzip file: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"I/O error: {e}", file=sys.stderr)
        return 1

    if args.verbose:
        print(f"Successfully wrote {written} line(s) to {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

